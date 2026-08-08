"""The triage agent: wires enrichment, scoring, narrative and actions together."""

from __future__ import annotations

import logging
import re
from typing import Any, List, Optional

from .actions import ActionExecutor, has_triage_label
from .config import TriageConfig, WorkspaceSettings, load_config
from .enrichment import Enricher
from .llm import LLMProvider, Narrative, apply_narrative, build_prompt, build_provider
from .models import Disposition, Enrichment, Incident, TriageResult, Verdict
from .rules import RuleEngine
from .sentinel import SentinelClient, incident_name_from_arm_id

logger = logging.getLogger(__name__)

_DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?)(d|h|m|s)$")
_DURATION_SECONDS = {"d": 86400, "h": 3600, "m": 60, "s": 1}


def duration_to_iso8601(value: str) -> str:
    """Convert a KQL timespan like ``4h`` into an ISO-8601 duration for OData."""
    match = _DURATION_RE.match(str(value).strip())
    if not match:
        raise ValueError(f"Not a supported duration: {value!r}")
    amount, unit = match.groups()
    seconds = float(amount) * _DURATION_SECONDS[unit]
    return f"PT{int(seconds)}S"


def duration_to_seconds(value: str) -> int:
    match = _DURATION_RE.match(str(value).strip())
    if not match:
        raise ValueError(f"Not a supported duration: {value!r}")
    amount, unit = match.groups()
    return int(float(amount) * _DURATION_SECONDS[unit])


class TriageAgent:
    """Triages one incident, or sweeps a window of them."""

    def __init__(
        self,
        client: Any,
        config: TriageConfig,
        llm: Optional[LLMProvider] = None,
    ) -> None:
        self.client = client
        self.config = config
        self.enricher = Enricher(client, config)
        self.engine = RuleEngine(config)
        self.llm = llm if llm is not None else build_provider(config)
        self.actions = ActionExecutor(client, config)

    # -- construction ------------------------------------------------------- #

    @classmethod
    def from_environment(
        cls, config_path: Optional[str] = None, env: Optional[dict] = None
    ) -> "TriageAgent":
        config = load_config(config_path, env)
        settings = WorkspaceSettings.from_env(env)
        client = SentinelClient(
            settings,
            query_timeout=int(config.enrichment.get("timeout_seconds", 90)),
        )
        return cls(client, config)

    # -- single incident ---------------------------------------------------- #

    def triage_incident(self, incident: Incident, *, hydrate: bool = True) -> TriageResult:
        """Run the full pipeline for one incident."""
        if hydrate and hasattr(self.client, "hydrate"):
            incident = self.client.hydrate(incident)

        enrichment = self.enricher.enrich(incident)
        verdict = self.engine.evaluate(incident, enrichment)
        verdict = self._add_narrative(incident, enrichment, verdict)

        result = TriageResult(incident=incident, enrichment=enrichment, verdict=verdict)
        result = self.actions.apply(result)
        logger.info(result.summary())
        return result

    def triage_by_name(self, incident_name: str) -> TriageResult:
        incident = self.client.get_incident(incident_name)
        return self.triage_incident(incident)

    def triage_by_arm_id(self, arm_id: str) -> TriageResult:
        return self.triage_by_name(incident_name_from_arm_id(arm_id))

    def _add_narrative(
        self, incident: Incident, enrichment: Enrichment, verdict: Verdict
    ) -> Verdict:
        if getattr(self.llm, "name", "none") == "none":
            verdict.narrative = self._template_narrative(incident, verdict)
            return verdict
        prompt = build_prompt(incident, enrichment, verdict)
        try:
            narrative = self.llm.generate(prompt)
        except Exception as exc:  # noqa: BLE001 - narrative is never load bearing
            logger.warning("LLM provider %r raised: %s", getattr(self.llm, "name", "?"), exc)
            narrative = Narrative(text="", error=str(exc))
        verdict = apply_narrative(verdict, narrative)
        if not verdict.narrative:
            verdict.narrative = self._template_narrative(incident, verdict)
        return verdict

    def _template_narrative(self, incident: Incident, verdict: Verdict) -> str:
        """Deterministic prose for rules-only deployments (and LLM failures)."""
        top = verdict.top_signals(limit=3)
        summary = {
            Disposition.LIKELY_FALSE_POSITIVE: (
                "The evidence points away from this being actionable."
            ),
            Disposition.NEEDS_REVIEW: (
                "The evidence is mixed; an analyst should look at this."
            ),
            Disposition.LIKELY_TRUE_POSITIVE: (
                "The evidence supports treating this as a real detection."
            ),
        }[verdict.disposition]

        parts = [summary]
        if top:
            drivers = "; ".join(f"{s.name} ({s.detail})" for s in top)
            parts.append(f"The strongest factors were: {drivers}.")
        if incident.entities:
            entities = ", ".join(str(e) for e in incident.entities[:4])
            parts.append(f"Entities involved: {entities}.")
        return " ".join(parts)

    # -- sweep -------------------------------------------------------------- #

    def poll(
        self,
        *,
        lookback: Optional[str] = None,
        max_incidents: Optional[int] = None,
    ) -> List[TriageResult]:
        """Triage recent, untriaged incidents.

        Idempotency comes from the triage labels the agent applies rather than
        from stored state: an incident that already carries one is skipped, so
        overlapping runs and replays are safe.
        """
        settings = self.config.polling
        lookback = lookback or str(settings.get("lookback", "4h"))
        limit = int(max_incidents or settings.get("max_incidents", 50))
        statuses = list(settings.get("statuses", ["New", "Active"]))

        filters = [f"properties/createdTimeUtc ge {self._since(lookback)}"]
        if statuses:
            status_clause = " or ".join(f"properties/status eq '{s}'" for s in statuses)
            filters.append(f"({status_clause})")
        odata = " and ".join(filters)

        logger.info("Polling incidents with filter: %s", odata)
        incidents = self.client.list_incidents(odata_filter=odata, top=limit)
        logger.info("Found %d incident(s) in the window", len(incidents))

        results: List[TriageResult] = []
        skip_labeled = bool(settings.get("skip_labeled", True))
        for incident in incidents:
            if skip_labeled and has_triage_label(self.config, incident):
                logger.debug("Skipping #%s: already triaged", incident.number)
                continue
            try:
                results.append(self.triage_incident(incident))
            except Exception as exc:  # noqa: BLE001 - one bad incident must not stop the sweep
                logger.exception("Triage failed for incident #%s", incident.number)
                results.append(
                    TriageResult(
                        incident=incident,
                        enrichment=Enrichment(),
                        verdict=Verdict(
                            disposition=Disposition.NEEDS_REVIEW,
                            score=50.0,
                            confidence=0.0,
                            rationale=[f"Triage failed: {exc}"],
                        ),
                        error=str(exc),
                    )
                )
        return results

    @staticmethod
    def _since(lookback: str) -> str:
        from datetime import datetime, timedelta, timezone

        moment = datetime.now(timezone.utc) - timedelta(seconds=duration_to_seconds(lookback))
        # Sentinel's OData filter wants an unquoted ISO-8601 instant.
        return moment.strftime("%Y-%m-%dT%H:%M:%SZ")
