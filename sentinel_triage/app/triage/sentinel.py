"""Azure clients for Sentinel incidents and Log Analytics queries.

Deliberately built on ``requests`` + ``azure-identity`` rather than the
management SDKs: two small dependencies keep Function cold starts short, and the
Sentinel incident REST surface we need is a handful of endpoints.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence

import requests

from .config import WorkspaceSettings
from .models import (
    Alert,
    Entity,
    EntityKind,
    Incident,
    dedupe,
    normalize_severity,
    parse_arm_time,
)

logger = logging.getLogger(__name__)

# Latest stable Sentinel incident API.
SENTINEL_API_VERSION = "2023-02-01"
WORKSPACE_API_VERSION = "2022-10-01"
LOGS_API_VERSION = "v1"

RETRY_STATUS = (408, 429, 500, 502, 503, 504)
MAX_ATTEMPTS = 4


class TransientAzureError(RuntimeError):
    """A request failed in a way that is worth retrying."""


class AzureRequestError(RuntimeError):
    """A request failed permanently."""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


# --------------------------------------------------------------------------- #
# Parsing (pure functions, usable offline for tests and replay)
# --------------------------------------------------------------------------- #

_ENTITY_VALUE_FIELDS = {
    EntityKind.IP: ["address"],
    EntityKind.ACCOUNT: ["accountName", "name", "friendlyName"],
    EntityKind.HOST: ["hostName", "netBiosName", "azureID", "friendlyName"],
    EntityKind.URL: ["url"],
    EntityKind.DNS: ["domainName"],
    EntityKind.FILE_HASH: ["hashValue"],
    EntityKind.FILE: ["fileName", "friendlyName"],
    EntityKind.PROCESS: ["commandLine", "friendlyName"],
    EntityKind.MAILBOX: ["mailboxPrimaryAddress", "upn", "friendlyName"],
    EntityKind.AZURE_RESOURCE: ["resourceId", "friendlyName"],
    EntityKind.CLOUD_APPLICATION: ["appName", "friendlyName"],
}


def _entity_kind(raw_kind: Any) -> EntityKind:
    text = str(raw_kind or "").strip()
    for kind in EntityKind:
        if kind.value.lower() == text.lower():
            return kind
    return EntityKind.OTHER


def parse_entity(payload: Dict[str, Any]) -> Optional[Entity]:
    """Build an :class:`Entity` from a Sentinel entity object.

    Returns ``None`` when no usable identifier can be extracted, so callers never
    have to reason about empty-valued entities.
    """
    if not isinstance(payload, dict):
        return None
    kind = _entity_kind(payload.get("kind"))
    props = payload.get("properties") or {}
    if not isinstance(props, dict):
        props = {}

    candidates = _ENTITY_VALUE_FIELDS.get(kind, []) + ["friendlyName", "name"]
    value = ""
    for field_name in candidates:
        candidate = props.get(field_name)
        if isinstance(candidate, str) and candidate.strip():
            value = candidate.strip()
            break

    # Accounts are far more useful as a UPN than a bare sAMAccountName.
    if kind == EntityKind.ACCOUNT and value:
        suffix = props.get("upnSuffix")
        if isinstance(suffix, str) and suffix.strip() and "@" not in value:
            value = f"{value}@{suffix.strip()}"

    if not value:
        return None
    return Entity(kind=kind, value=value, properties=props)


def parse_alert(payload: Dict[str, Any]) -> Optional[Alert]:
    """Build an :class:`Alert` from a Sentinel alert object."""
    if not isinstance(payload, dict):
        return None
    props = payload.get("properties") or {}
    if not isinstance(props, dict):
        props = {}
    name = props.get("alertDisplayName") or props.get("friendlyName") or payload.get("name") or ""
    if not name:
        return None

    tactics = props.get("tactics") or []
    techniques = props.get("techniques") or props.get("subTechniques") or []
    return Alert(
        id=str(payload.get("id") or props.get("systemAlertId") or name),
        name=str(name),
        severity=normalize_severity(props.get("alertSeverity") or props.get("severity")),
        tactics=[str(t) for t in tactics if t],
        techniques=[str(t) for t in techniques if t],
        product_name=props.get("productName"),
        start_time=parse_arm_time(props.get("startTimeUtc")),
        end_time=parse_arm_time(props.get("endTimeUtc")),
        description=props.get("description"),
    )


def parse_incident(payload: Dict[str, Any]) -> Incident:
    """Build an :class:`Incident` from an ARM incident resource.

    Also accepts a Logic App Sentinel-trigger body, which nests the resource
    under ``object``.
    """
    if not isinstance(payload, dict):
        raise ValueError("Incident payload must be an object")

    # Logic App trigger bodies wrap the resource.
    if "object" in payload and isinstance(payload["object"], dict):
        payload = payload["object"]

    props = payload.get("properties") or {}
    if not isinstance(props, dict):
        props = {}

    additional = props.get("additionalData") or {}
    if not isinstance(additional, dict):
        additional = {}

    rule_ids = [str(r) for r in (props.get("relatedAnalyticRuleIds") or []) if r]
    rule_names = [str(n) for n in (additional.get("alertProductNames") or []) if n]
    # alertProductNames is the product, not the rule; prefer explicit rule names
    # when the payload carries them (the Logic App trigger does).
    explicit_rules = props.get("alertRuleNames") or additional.get("alertRuleNames") or []
    if explicit_rules:
        rule_names = [str(n) for n in explicit_rules if n]

    owner = props.get("owner") or {}
    if not isinstance(owner, dict):
        owner = {}

    incident = Incident(
        arm_id=str(payload.get("id") or ""),
        name=str(payload.get("name") or ""),
        number=int(props.get("incidentNumber") or 0),
        title=str(props.get("title") or ""),
        severity=normalize_severity(props.get("severity")),
        status=str(props.get("status") or "New"),
        description=str(props.get("description") or ""),
        labels=[
            str(label.get("labelName"))
            for label in (props.get("labels") or [])
            if isinstance(label, dict) and label.get("labelName")
        ],
        classification=props.get("classification"),
        classification_reason=props.get("classificationReason"),
        owner=owner,
        created_time=parse_arm_time(props.get("createdTimeUtc")),
        last_modified_time=parse_arm_time(props.get("lastModifiedTimeUtc")),
        first_activity_time=parse_arm_time(props.get("firstActivityTimeUtc")),
        alert_rule_ids=rule_ids,
        alert_rule_names=dedupe(rule_names),
        alert_count=int(additional.get("alertsCount") or 0),
        provider_name=props.get("providerName"),
        incident_url=props.get("incidentUrl"),
        etag=payload.get("etag") or props.get("etag"),
        raw=payload,
    )

    # Some payloads (Logic App trigger) inline alerts and entities.
    for raw_alert in props.get("alerts") or []:
        alert = parse_alert(raw_alert)
        if alert:
            incident.alerts.append(alert)
    for raw_entity in props.get("entities") or []:
        entity = parse_entity(raw_entity)
        if entity:
            incident.entities.append(entity)

    if not incident.alert_count:
        incident.alert_count = len(incident.alerts)
    return incident


def incident_name_from_arm_id(arm_id: str) -> str:
    """Extract the incident GUID from an ARM resource id."""
    parts = [p for p in str(arm_id).split("/") if p]
    if not parts:
        raise ValueError(f"Not a valid incident ARM id: {arm_id!r}")
    if "incidents" not in parts:
        raise ValueError(f"ARM id does not point at an incident: {arm_id!r}")
    index = len(parts) - 1 - parts[::-1].index("incidents")
    if index + 1 >= len(parts):
        raise ValueError(f"ARM id is missing the incident name: {arm_id!r}")
    return parts[index + 1]


# --------------------------------------------------------------------------- #
# Credential handling
# --------------------------------------------------------------------------- #


class TokenSource(Protocol):
    """Minimal credential surface, so tests can pass a stub."""

    def get_token(self, *scopes: str) -> Any: ...


class _TokenCache:
    """Caches bearer tokens per scope until shortly before expiry."""

    def __init__(self, credential: TokenSource) -> None:
        self._credential = credential
        self._lock = threading.Lock()
        self._tokens: Dict[str, Any] = {}

    def bearer(self, scope: str) -> str:
        with self._lock:
            cached = self._tokens.get(scope)
            # Refresh 5 minutes early to avoid mid-flight expiry.
            if cached is not None and cached.expires_on - time.time() > 300:
                return cached.token
            token = self._credential.get_token(scope)
            self._tokens[scope] = token
            return token.token


def default_credential() -> TokenSource:
    """Managed identity in Azure, developer credentials locally."""
    from azure.identity import DefaultAzureCredential

    client_id = None
    import os

    # A user-assigned identity needs its client id passed explicitly.
    if os.environ.get("AZURE_CLIENT_ID"):
        client_id = os.environ["AZURE_CLIENT_ID"]
    return DefaultAzureCredential(managed_identity_client_id=client_id)


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #


class SentinelClient:
    """Read and update Sentinel incidents, and run KQL against the workspace."""

    def __init__(
        self,
        settings: WorkspaceSettings,
        credential: Optional[TokenSource] = None,
        session: Optional[requests.Session] = None,
        query_timeout: int = 90,
    ) -> None:
        self.settings = settings
        self._tokens = _TokenCache(credential or default_credential())
        self._session = session or requests.Session()
        self._query_timeout = query_timeout
        self._workspace_guid: Optional[str] = settings.workspace_id or None

    # -- plumbing ---------------------------------------------------------- #

    def _request(
        self,
        method: str,
        url: str,
        scope: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        timeout: int = 60,
    ) -> Any:
        headers = {
            "Authorization": f"Bearer {self._tokens.bearer(scope)}",
            "Content-Type": "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)

        last_error: Optional[Exception] = None
        for attempt in range(MAX_ATTEMPTS):
            try:
                response = self._session.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers=headers,
                    timeout=timeout,
                )
            except requests.RequestException as exc:
                last_error = TransientAzureError(f"{method} {url} failed: {exc}")
            else:
                if response.status_code in RETRY_STATUS:
                    last_error = TransientAzureError(
                        f"{method} {url} returned {response.status_code}: {response.text[:400]}"
                    )
                    # Honour Retry-After when the service tells us how long to wait.
                    retry_after = response.headers.get("Retry-After")
                    if retry_after and attempt < MAX_ATTEMPTS - 1:
                        try:
                            time.sleep(min(float(retry_after), 30.0))
                            continue
                        except ValueError:
                            pass
                elif not response.ok:
                    raise AzureRequestError(
                        f"{method} {url} returned {response.status_code}: {response.text[:800]}",
                        status_code=response.status_code,
                    )
                else:
                    if not response.content:
                        return None
                    return response.json()

            if attempt < MAX_ATTEMPTS - 1:
                backoff = (2**attempt) + random.uniform(0, 0.5)
                logger.warning(
                    "Retrying %s %s in %.1fs (attempt %d/%d)",
                    method,
                    url,
                    backoff,
                    attempt + 1,
                    MAX_ATTEMPTS,
                )
                time.sleep(backoff)

        raise AzureRequestError(str(last_error) if last_error else f"{method} {url} failed")

    def _arm(self, path: str) -> str:
        return f"{self.settings.arm_endpoint}{path}"

    @property
    def _arm_scope(self) -> str:
        return f"{self.settings.arm_endpoint}/.default"

    @property
    def _logs_scope(self) -> str:
        return f"{self.settings.logs_endpoint}/.default"

    # -- incidents --------------------------------------------------------- #

    def workspace_guid(self) -> str:
        """Resolve the Log Analytics customer id, caching it for the process."""
        if self._workspace_guid:
            return self._workspace_guid
        payload = self._request(
            "GET",
            self._arm(self.settings.workspace_arm_id),
            self._arm_scope,
            params={"api-version": WORKSPACE_API_VERSION},
        )
        guid = ((payload or {}).get("properties") or {}).get("customerId")
        if not guid:
            raise AzureRequestError(
                f"Could not resolve workspace id for {self.settings.workspace_name}"
            )
        self._workspace_guid = str(guid)
        return self._workspace_guid

    def get_incident(self, incident_name: str) -> Incident:
        payload = self._request(
            "GET",
            self._arm(f"{self.settings.sentinel_base}/incidents/{incident_name}"),
            self._arm_scope,
            params={"api-version": SENTINEL_API_VERSION},
        )
        return parse_incident(payload)

    def list_incidents(
        self,
        *,
        odata_filter: Optional[str] = None,
        top: int = 50,
        order_by: str = "properties/createdTimeUtc desc",
    ) -> List[Incident]:
        """List incidents, following ``nextLink`` until ``top`` are collected."""
        params: Dict[str, Any] = {
            "api-version": SENTINEL_API_VERSION,
            "$top": min(top, 100),
            "$orderby": order_by,
        }
        if odata_filter:
            params["$filter"] = odata_filter

        url = self._arm(f"{self.settings.sentinel_base}/incidents")
        incidents: List[Incident] = []
        while url and len(incidents) < top:
            payload = self._request("GET", url, self._arm_scope, params=params) or {}
            for item in payload.get("value") or []:
                incidents.append(parse_incident(item))
                if len(incidents) >= top:
                    break
            url = payload.get("nextLink") or ""
            # nextLink already carries the query string.
            params = {}
        return incidents

    def get_incident_entities(self, incident_name: str) -> List[Entity]:
        payload = self._request(
            "POST",
            self._arm(f"{self.settings.sentinel_base}/incidents/{incident_name}/entities"),
            self._arm_scope,
            params={"api-version": SENTINEL_API_VERSION},
        ) or {}
        entities = []
        for raw in payload.get("entities") or []:
            entity = parse_entity(raw)
            if entity:
                entities.append(entity)
        return entities

    def get_incident_alerts(self, incident_name: str) -> List[Alert]:
        payload = self._request(
            "POST",
            self._arm(f"{self.settings.sentinel_base}/incidents/{incident_name}/alerts"),
            self._arm_scope,
            params={"api-version": SENTINEL_API_VERSION},
        ) or {}
        alerts = []
        for raw in payload.get("value") or []:
            alert = parse_alert(raw)
            if alert:
                alerts.append(alert)
        return alerts

    def hydrate(self, incident: Incident) -> Incident:
        """Fill in alerts and entities, which the incident resource omits.

        Failures here are logged and swallowed: partial context still produces a
        useful (lower-confidence) verdict.
        """
        if not incident.name:
            return incident
        try:
            alerts = self.get_incident_alerts(incident.name)
            if alerts:
                incident.alerts = alerts
                incident.alert_count = max(incident.alert_count, len(alerts))
                # The alert display names are the analytics rule names we need
                # for historical FP lookups.
                names = dedupe([a.name for a in alerts])
                if names:
                    incident.alert_rule_names = names
        except Exception as exc:  # noqa: BLE001 - enrichment is best effort
            logger.warning("Could not load alerts for incident %s: %s", incident.name, exc)
        try:
            entities = self.get_incident_entities(incident.name)
            if entities:
                incident.entities = entities
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not load entities for incident %s: %s", incident.name, exc)
        return incident

    # -- writes ------------------------------------------------------------ #

    def add_comment(self, incident_name: str, message: str, comment_id: str) -> Dict[str, Any]:
        """Add (or overwrite) a comment. ``comment_id`` makes this idempotent."""
        return self._request(
            "PUT",
            self._arm(
                f"{self.settings.sentinel_base}/incidents/{incident_name}/comments/{comment_id}"
            ),
            self._arm_scope,
            params={"api-version": SENTINEL_API_VERSION},
            json_body={"properties": {"message": message}},
        )

    def update_incident(
        self,
        incident: Incident,
        *,
        labels: Optional[Sequence[str]] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        classification: Optional[str] = None,
        classification_reason: Optional[str] = None,
        classification_comment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update an incident.

        Sentinel's incident PUT replaces the whole properties bag, so the current
        values for title/severity/status are always resent. The ETag is included
        so a concurrent analyst edit fails the write instead of clobbering it.
        """
        props: Dict[str, Any] = {
            "title": incident.title,
            "severity": severity or incident.severity,
            "status": status or incident.status,
        }
        if incident.description:
            props["description"] = incident.description
        if incident.owner:
            props["owner"] = incident.owner

        merged_labels = list(incident.labels)
        for label in labels or []:
            if label not in merged_labels:
                merged_labels.append(label)
        if merged_labels:
            props["labels"] = [{"labelName": name, "labelType": "User"} for name in merged_labels]

        if (status or incident.status) == "Closed":
            props["classification"] = classification or "Undetermined"
            if classification_reason:
                props["classificationReason"] = classification_reason
            if classification_comment:
                props["classificationComment"] = classification_comment

        body: Dict[str, Any] = {"properties": props}
        if incident.etag:
            body["etag"] = incident.etag

        return self._request(
            "PUT",
            self._arm(f"{self.settings.sentinel_base}/incidents/{incident.name}"),
            self._arm_scope,
            params={"api-version": SENTINEL_API_VERSION},
            json_body=body,
        )

    # -- log analytics ----------------------------------------------------- #

    def query_logs(self, kql: str, timespan: Optional[str] = None) -> List[Dict[str, Any]]:
        """Run a KQL query and return the primary table as a list of dicts."""
        url = (
            f"{self.settings.logs_endpoint}/{LOGS_API_VERSION}"
            f"/workspaces/{self.workspace_guid()}/query"
        )
        body: Dict[str, Any] = {"query": kql}
        if timespan:
            body["timespan"] = timespan

        payload = self._request(
            "POST",
            url,
            self._logs_scope,
            json_body=body,
            # Ask the service to wait rather than returning a partial result.
            extra_headers={"Prefer": f"wait={self._query_timeout}"},
            timeout=self._query_timeout + 15,
        ) or {}
        return rows_from_logs_response(payload)


def rows_from_logs_response(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert a Log Analytics query response into row dicts."""
    tables = payload.get("tables") or []
    if not tables:
        return []
    table = tables[0]
    columns = [col.get("name") for col in table.get("columns") or []]
    rows = []
    for values in table.get("rows") or []:
        rows.append({name: value for name, value in zip(columns, values)})
    return rows


def kql_string_list(values: Iterable[str]) -> str:
    """Render values as a KQL ``dynamic([...])`` literal.

    Values are JSON-escaped, which is what makes it safe to interpolate
    entity-derived strings into a query.
    """
    import json

    cleaned = [str(v) for v in values if str(v).strip()]
    return "dynamic(" + json.dumps(cleaned) + ")"


def kql_literal(value: str) -> str:
    """Render a single string as a JSON-escaped KQL literal."""
    import json

    return json.dumps(str(value))
