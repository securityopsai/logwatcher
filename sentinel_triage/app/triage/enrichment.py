"""KQL enrichment: gather the evidence the rule engine scores.

Query notes
-----------
``SecurityIncident`` holds one row per incident *update*, not per incident. Every
query over it therefore collapses to the latest row per ``IncidentNumber`` with
``arg_max`` before counting, otherwise a single much-edited incident inflates the
statistics.

Entity values inside ``SecurityIncident.Entities`` come from parsed JSON, so
missing keys are genuine nulls and ``coalesce`` is safe. Threat-intel tables use
empty strings for unset columns, so those need ``case(isnotempty(...))`` instead.

Optional tables are referenced through ``union isfuzzy=true`` so a workspace that
does not ingest them degrades to "no rows" rather than a failing query.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Sequence

from .config import TriageConfig
from .models import (
    Enrichment,
    EntityKind,
    EntityPrevalence,
    Incident,
    PriorClosure,
    RelatedIncident,
    RuleFpHistory,
    ThreatIntelHit,
    normalize_severity,
    parse_arm_time,
)
from .sentinel import kql_literal, kql_string_list

logger = logging.getLogger(__name__)

# Shared KQL fragment: pull a comparable value out of a SecurityIncident entity.
# Both PascalCase (SecurityIncident/SecurityAlert) and camelCase (API) spellings
# appear in the wild, so both are tried.
_ENTITY_VALUE_EXPR = """
| extend EntityValue = tolower(tostring(coalesce(
      Entity.Address, Entity.address,
      Entity.HostName, Entity.hostName,
      Entity.Name, Entity.accountName,
      Entity.Url, Entity.url,
      Entity.DomainName, Entity.domainName,
      Entity.Value)))
| extend EntityUpn = tolower(strcat(
      tostring(coalesce(Entity.Name, Entity.accountName)), "@",
      tostring(coalesce(Entity.UPNSuffix, Entity.upnSuffix))))
"""


class Enricher:
    """Runs the enrichment queries for one incident.

    Every query is individually guarded: a failure is recorded on the
    :class:`Enrichment` (which lowers verdict confidence) instead of aborting
    triage.
    """

    def __init__(self, client: Any, config: TriageConfig) -> None:
        self.client = client
        self.config = config

    # -- entry point -------------------------------------------------------- #

    def enrich(self, incident: Incident) -> Enrichment:
        enrichment = Enrichment()
        if not self.config.enrichment.get("enabled", True):
            logger.info("Enrichment disabled by config; scoring on incident metadata only")
            return enrichment

        limit = int(self.config.enrichment.get("max_entities_per_query", 25))
        ips = incident.entity_values(EntityKind.IP)[:limit]
        accounts = incident.entity_values(EntityKind.ACCOUNT)[:limit]
        hosts = incident.entity_values(EntityKind.HOST)[:limit]
        network_ish = incident.entity_values(
            EntityKind.IP, EntityKind.URL, EntityKind.DNS, EntityKind.FILE_HASH
        )[:limit]
        all_entities = incident.entity_values()[:limit]

        rule_name = incident.primary_rule_name

        if rule_name:
            self._run(
                enrichment,
                "rule_history",
                lambda: self._rule_history(enrichment, rule_name),
            )
            if all_entities:
                self._run(
                    enrichment,
                    "prior_closures",
                    lambda: self._prior_closures(enrichment, rule_name, all_entities),
                )
        else:
            logger.info(
                "Incident #%s has no analytics rule name; skipping history queries",
                incident.number,
            )

        if all_entities:
            self._run(
                enrichment,
                "related_incidents",
                lambda: self._related_incidents(enrichment, incident, all_entities),
            )
        if network_ish:
            self._run(
                enrichment,
                "threat_intel",
                lambda: self._threat_intel(enrichment, network_ish),
            )
        if ips:
            self._run(
                enrichment,
                "ip_prevalence",
                lambda: self._prevalence(
                    enrichment,
                    ips,
                    self.config.enrichment.get("ip_prevalence_sources", []),
                    enrichment.ip_prevalence,
                    case_insensitive=False,
                ),
            )
        if accounts:
            self._run(
                enrichment,
                "account_prevalence",
                lambda: self._prevalence(
                    enrichment,
                    accounts,
                    self.config.enrichment.get("account_prevalence_sources", []),
                    enrichment.account_prevalence,
                    case_insensitive=True,
                ),
            )

        logger.info(
            "Enrichment for #%s: %d ok, %d failed (%.0f%% complete)",
            incident.number,
            len(enrichment.completed),
            len(enrichment.failures),
            enrichment.completeness * 100,
        )
        _ = hosts  # hosts participate via all_entities; kept for readability
        return enrichment

    def _run(self, enrichment: Enrichment, name: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - one bad query must not stop triage
            logger.warning("Enrichment query %r failed: %s", name, exc)
            enrichment.mark_failed(name, str(exc)[:300])
        else:
            enrichment.mark_ok(name)

    def _query(self, kql: str) -> List[Dict[str, Any]]:
        return self.client.query_logs(kql)

    # -- individual queries ------------------------------------------------- #

    def _rule_history(self, enrichment: Enrichment, rule_name: str) -> None:
        """How previous incidents from this analytics rule were dispositioned."""
        kql = f"""
let lookback = {self.config.lookback('rule_history')};
let ruleName = {kql_literal(rule_name)};
SecurityIncident
| where TimeGenerated > ago(lookback)
| where AlertRuleNames has ruleName
| summarize arg_max(TimeGenerated, Status, Classification, AlertRuleNames) by IncidentNumber
| where array_index_of(AlertRuleNames, ruleName) >= 0
| where Status == "Closed"
| summarize
    Closed = count(),
    FalsePositive = countif(Classification == "FalsePositive"),
    BenignPositive = countif(Classification == "BenignPositive"),
    TruePositive = countif(Classification == "TruePositive"),
    Undetermined = countif(Classification == "Undetermined" or isempty(Classification))
""".strip()
        rows = self._query(kql)
        if not rows:
            enrichment.rule_history = RuleFpHistory(rule_name=rule_name)
            return
        row = rows[0]
        enrichment.rule_history = RuleFpHistory(
            rule_name=rule_name,
            closed=int(row.get("Closed") or 0),
            false_positive=int(row.get("FalsePositive") or 0),
            benign_positive=int(row.get("BenignPositive") or 0),
            true_positive=int(row.get("TruePositive") or 0),
            undetermined=int(row.get("Undetermined") or 0),
        )

    def _prior_closures(
        self, enrichment: Enrichment, rule_name: str, entities: Sequence[str]
    ) -> None:
        """Same rule + same entity previously closed as not-actionable."""
        kql = f"""
let lookback = {self.config.lookback('prior_closures')};
let ruleName = {kql_literal(rule_name)};
let targets = {kql_string_list(entities)};
SecurityIncident
| where TimeGenerated > ago(lookback)
| where AlertRuleNames has ruleName
| summarize arg_max(TimeGenerated, Status, Classification, ClassificationReason, Entities, AlertRuleNames)
    by IncidentNumber
| where Status == "Closed" and Classification in ("FalsePositive", "BenignPositive")
| where array_index_of(AlertRuleNames, ruleName) >= 0
| mv-expand Entity = Entities
{_ENTITY_VALUE_EXPR.strip()}
| where EntityValue in (targets) or EntityUpn in (targets)
| extend MatchedEntity = iff(EntityValue in (targets), EntityValue, EntityUpn)
| summarize arg_max(TimeGenerated, Classification, ClassificationReason)
    by MatchedEntity, IncidentNumber
| top 50 by TimeGenerated desc
""".strip()
        for row in self._query(kql):
            enrichment.prior_closures.append(
                PriorClosure(
                    entity=str(row.get("MatchedEntity") or ""),
                    incident_number=int(row.get("IncidentNumber") or 0),
                    classification=str(row.get("Classification") or ""),
                    closed_time=parse_arm_time(row.get("TimeGenerated")),
                    reason=row.get("ClassificationReason"),
                )
            )

    def _related_incidents(
        self, enrichment: Enrichment, incident: Incident, entities: Sequence[str]
    ) -> None:
        """Other still-open incidents sharing an entity with this one."""
        kql = f"""
let lookback = {self.config.lookback('related_incidents')};
let targets = {kql_string_list(entities)};
let currentIncident = {int(incident.number)};
SecurityIncident
| where TimeGenerated > ago(lookback)
| summarize arg_max(TimeGenerated, Status, Severity, Title, Entities) by IncidentNumber
| where Status in ("New", "Active") and IncidentNumber != currentIncident
| mv-expand Entity = Entities
{_ENTITY_VALUE_EXPR.strip()}
| where EntityValue in (targets) or EntityUpn in (targets)
| extend MatchedEntity = iff(EntityValue in (targets), EntityValue, EntityUpn)
| summarize SharedEntities = make_set(MatchedEntity, 10), Title = any(Title), Severity = any(Severity)
    by IncidentNumber
| top 25 by IncidentNumber desc
""".strip()
        for row in self._query(kql):
            shared = row.get("SharedEntities") or []
            if isinstance(shared, str):
                shared = [shared]
            enrichment.related_incidents.append(
                RelatedIncident(
                    incident_number=int(row.get("IncidentNumber") or 0),
                    title=str(row.get("Title") or ""),
                    severity=normalize_severity(row.get("Severity")),
                    shared_entities=[str(s) for s in shared],
                )
            )

    def _threat_intel(self, enrichment: Enrichment, entities: Sequence[str]) -> None:
        """Match network/file entities against ingested threat intelligence.

        Covers both the legacy ``ThreatIntelligenceIndicator`` table and the
        STIX-based ``ThreatIntelIndicators`` that replaces it.
        """
        kql = f"""
let lookback = {self.config.lookback('threat_intel')};
let targets = {kql_string_list(entities)};
union isfuzzy=true
    (
        ThreatIntelligenceIndicator
        | where TimeGenerated > ago(lookback)
        | where Active == true
        | extend Indicator = tolower(case(
            isnotempty(NetworkIP), NetworkIP,
            isnotempty(NetworkSourceIP), NetworkSourceIP,
            isnotempty(NetworkDestinationIP), NetworkDestinationIP,
            isnotempty(Url), Url,
            isnotempty(DomainName), DomainName,
            isnotempty(FileHashValue), FileHashValue,
            ""))
        | where Indicator in (targets)
        | project TimeGenerated, Indicator, ThreatType, Confidence = toreal(ConfidenceScore),
                  Description, Source = SourceSystem, ExpiresOn = ExpirationDateTime
    ),
    (
        ThreatIntelIndicators
        | where TimeGenerated > ago(lookback)
        | where IsActive == true
        | extend Indicator = tolower(tostring(ObservableValue))
        | where Indicator in (targets)
        | project TimeGenerated, Indicator, ThreatType = tostring(Data.indicator_types[0]),
                  Confidence = toreal(Confidence), Description = tostring(Data.description),
                  Source = tostring(SourceSystem), ExpiresOn = ValidUntil
    )
| where isnull(ExpiresOn) or ExpiresOn > now()
| summarize arg_max(TimeGenerated, ThreatType, Confidence, Description, Source) by Indicator
| top 20 by TimeGenerated desc
""".strip()
        for row in self._query(kql):
            confidence = row.get("Confidence")
            enrichment.threat_intel.append(
                ThreatIntelHit(
                    entity=str(row.get("Indicator") or ""),
                    threat_type=row.get("ThreatType"),
                    confidence=float(confidence) if confidence is not None else None,
                    source=row.get("Source"),
                    description=row.get("Description"),
                )
            )

    def _prevalence(
        self,
        enrichment: Enrichment,
        entities: Sequence[str],
        sources: Sequence[Dict[str, str]],
        target: Dict[str, EntityPrevalence],
        *,
        case_insensitive: bool,
    ) -> None:
        """How much history the workspace has for these entities.

        ``sources`` is config-driven; the config schema constrains table and
        column names to bare identifiers, which is what makes interpolating them
        into KQL safe.
        """
        if not sources:
            return
        operator = "in~" if case_insensitive else "in"
        legs = []
        for source in sources:
            table = source["table"]
            column = source["column"]
            legs.append(
                f"    ({table}\n"
                f"     | where TimeGenerated > ago(lookback)\n"
                f"     | where {column} {operator} (targets)\n"
                f"     | project TimeGenerated, Value = tolower(tostring({column})))"
            )

        # Built outside the f-string: backslash escapes in f-string expressions
        # are only legal from Python 3.12.
        union_legs = ",\n".join(legs)
        kql = f"""
let lookback = {self.config.lookback('prevalence')};
let targets = {kql_string_list(entities)};
union isfuzzy=true
{union_legs}
| summarize Events = count(), DistinctDays = dcount(bin(TimeGenerated, 1d)),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by Value
""".strip()
        for row in self._query(kql):
            value = str(row.get("Value") or "")
            if not value:
                continue
            target[value] = EntityPrevalence(
                entity=value,
                events=int(row.get("Events") or 0),
                distinct_days=int(row.get("DistinctDays") or 0),
                first_seen=parse_arm_time(row.get("FirstSeen")),
                last_seen=parse_arm_time(row.get("LastSeen")),
            )
