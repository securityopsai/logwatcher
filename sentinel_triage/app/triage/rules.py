"""The deterministic triage engine.

Design constraints, in priority order:

1. **Explainable.** Every point of the score traces back to a named
   :class:`~triage.models.Signal` with human-readable evidence. There is no
   opaque term.
2. **Asymmetric safety.** Thin evidence can never produce a false-positive
   verdict, but it can still produce an escalation. Being wrong toward "look at
   this" is cheap; being wrong toward "ignore this" is not.
3. **Deterministic.** Same incident plus same enrichment always yields the same
   verdict, so the engine is unit testable and its behaviour is auditable.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import List, Optional, Sequence, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .config import Suppression, TriageConfig
from .models import (
    SEVERITY_ORDER,
    Disposition,
    Enrichment,
    Entity,
    EntityKind,
    Incident,
    Signal,
    Verdict,
)

logger = logging.getLogger(__name__)

# Enrichment queries whose absence most weakens a benign verdict. Confidence is
# penalised specifically when these are missing rather than treating every query
# as equally important.
CRITICAL_QUERIES = ("rule_history", "prior_closures", "related_incidents")


class RuleEngine:
    """Scores an incident from its metadata plus enrichment evidence."""

    def __init__(self, config: TriageConfig) -> None:
        self.config = config

    # -- entry point -------------------------------------------------------- #

    def evaluate(self, incident: Incident, enrichment: Enrichment) -> Verdict:
        signals: List[Signal] = []
        rationale: List[str] = []

        baseline = self._baseline(incident)
        score = baseline
        rationale.append(
            f"Baseline {baseline:.0f} from incident severity {incident.severity}."
        )

        collectors = (
            self._signal_suppression,
            self._signal_known_good,
            self._signal_prior_closures,
            self._signal_rule_history,
            self._signal_threat_intel,
            self._signal_related_incidents,
            self._signal_high_value_asset,
            self._signal_multi_tactic,
            self._signal_alert_volume,
            self._signal_service_account,
            self._signal_ip_disposition,
            self._signal_prevalence,
            self._signal_off_hours,
        )
        for collector in collectors:
            signals.extend(collector(incident, enrichment))

        hard_suppression = next(
            (s for s in signals if s.name == "suppression_rule"), None
        )

        for signal in signals:
            score += signal.points
        score = _clamp(score, 0, 100)

        confidence = self._confidence(incident, enrichment, signals)

        if hard_suppression is not None:
            # A configured suppression is an operator decision, not an inference.
            score = min(score, self.config.thresholds["false_positive_max"])
            confidence = max(confidence, 90.0)
            rationale.append(f"Suppression rule matched: {hard_suppression.detail}")

        disposition, decision_notes = self._decide(score, confidence)
        rationale.extend(decision_notes)

        verdict = Verdict(
            disposition=disposition,
            score=round(score, 1),
            confidence=round(confidence, 1),
            signals=signals,
            rationale=rationale,
        )
        if self.config.actions.get("suggest_severity", True):
            verdict.suggested_severity = self._suggest_severity(incident, score)
        return verdict

    # -- score assembly ----------------------------------------------------- #

    def _baseline(self, incident: Incident) -> float:
        table = self.config.scoring["baseline_by_severity"]
        return float(table.get(incident.severity, table.get("Medium", 45)))

    def _decide(self, score: float, confidence: float) -> Tuple[Disposition, List[str]]:
        thresholds = self.config.thresholds
        fp_max = float(thresholds["false_positive_max"])
        tp_min = float(thresholds["true_positive_min"])
        min_conf = float(thresholds["min_confidence_for_fp"])
        notes: List[str] = []

        if score >= tp_min:
            notes.append(f"Score {score:.0f} >= {tp_min:.0f}, escalating.")
            return Disposition.LIKELY_TRUE_POSITIVE, notes
        if score <= fp_max:
            if confidence < min_conf:
                notes.append(
                    f"Score {score:.0f} suggests a false positive, but confidence "
                    f"{confidence:.0f} is below the {min_conf:.0f} required to say so. "
                    "Downgraded to needs-review."
                )
                return Disposition.NEEDS_REVIEW, notes
            notes.append(
                f"Score {score:.0f} <= {fp_max:.0f} with confidence {confidence:.0f}."
            )
            return Disposition.LIKELY_FALSE_POSITIVE, notes
        notes.append(
            f"Score {score:.0f} sits between {fp_max:.0f} and {tp_min:.0f}; no confident call."
        )
        return Disposition.NEEDS_REVIEW, notes

    def _confidence(
        self, incident: Incident, enrichment: Enrichment, signals: Sequence[Signal]
    ) -> float:
        """How much the evidence supports the score.

        Starts from how much enrichment succeeded, then adjusts for how much
        context the incident itself carried.
        """
        if not self.config.enrichment.get("enabled", True):
            # Metadata-only triage is honest but weak evidence.
            base = 35.0
        elif enrichment.attempted == 0:
            base = 30.0
        else:
            base = 40.0 + 45.0 * enrichment.completeness

        # Missing high-value queries hurt more than missing prevalence lookups.
        for name in CRITICAL_QUERIES:
            if name in enrichment.failures:
                base -= 12.0

        if not incident.entities:
            base -= 15.0
        if not incident.alert_rule_names:
            base -= 10.0

        history = enrichment.rule_history
        min_closed = int(self.config.scoring.get("min_closed_for_history", 5))
        if history is not None and history.closed >= min_closed:
            base += 8.0

        # Config-derived signals (allowlists, suppressions) are operator
        # assertions and carry their own certainty.
        if any(s.from_config and s.points for s in signals):
            base += 10.0

        return _clamp(base, 0, 100)

    def _suggest_severity(self, incident: Incident, score: float) -> Optional[str]:
        """Propose a severity that matches the score, if it differs from current."""
        if score >= 80:
            proposed = "High"
        elif score >= 55:
            proposed = "Medium"
        elif score >= 30:
            proposed = "Low"
        else:
            proposed = "Informational"
        return proposed if proposed != incident.severity else None

    # -- individual signals -------------------------------------------------- #

    def _signal_suppression(
        self, incident: Incident, enrichment: Enrichment
    ) -> List[Signal]:
        for suppression in self.config.suppressions:
            if self._suppression_matches(suppression, incident):
                return [
                    Signal(
                        name="suppression_rule",
                        points=0.0,  # applied as a hard override, not a weight
                        detail=f"{suppression.name} - {suppression.reason}",
                        from_config=True,
                    )
                ]
        return []

    def _suppression_matches(self, suppression: Suppression, incident: Incident) -> bool:
        """All specified conditions must match; unspecified conditions are ignored."""
        if suppression.rule_names:
            if not any(
                matches_any(name, suppression.rule_names)
                for name in incident.alert_rule_names
            ):
                return False
        if suppression.titles and not matches_any(incident.title, suppression.titles):
            return False
        if suppression.max_severity:
            ceiling = _severity_rank(suppression.max_severity)
            if _severity_rank(incident.severity) > ceiling:
                return False

        entity_conditions = bool(
            suppression.ip_ranges or suppression.accounts or suppression.hosts
        )
        if not entity_conditions:
            # No entity constraints: the rule/title/severity match is enough.
            return bool(suppression.rule_names or suppression.titles or suppression.max_severity)

        # Every declared entity condition must find a match on the incident.
        if suppression.ip_ranges:
            ips = incident.entities_of(EntityKind.IP)
            if not ips or not all(
                _ip_in_any(entity.value, suppression.ip_ranges) for entity in ips
            ):
                return False
        if suppression.accounts:
            accounts = incident.entity_values(EntityKind.ACCOUNT)
            if not accounts or not all(
                matches_any(value, suppression.accounts) for value in accounts
            ):
                return False
        if suppression.hosts:
            hosts = incident.entity_values(EntityKind.HOST)
            if not hosts or not all(
                matches_any(value, suppression.hosts) for value in hosts
            ):
                return False
        return True

    def _signal_known_good(self, incident: Incident, enrichment: Enrichment) -> List[Signal]:
        """Every entity of a given kind sits on the allowlist."""
        matched: List[str] = []

        ips = incident.entities_of(EntityKind.IP)
        if ips and self.config.known_good_networks:
            if all(_ip_in_networks(e.value, self.config.known_good_networks) for e in ips):
                matched.append(f"all {len(ips)} IP(s) in known-good ranges")

        accounts = incident.entity_values(EntityKind.ACCOUNT)
        if accounts and self.config.known_good_accounts:
            if all(_regex_any(v, self.config.known_good_accounts) for v in accounts):
                matched.append(f"all {len(accounts)} account(s) allowlisted")

        hosts = incident.entity_values(EntityKind.HOST)
        if hosts and self.config.known_good_hosts:
            if all(_regex_any(v, self.config.known_good_hosts) for v in hosts):
                matched.append(f"all {len(hosts)} host(s) allowlisted")

        domains = incident.entity_values(EntityKind.DNS, EntityKind.URL)
        if domains and self.config.known_good_domains:
            if all(_regex_any(v, self.config.known_good_domains) for v in domains):
                matched.append(f"all {len(domains)} domain(s)/URL(s) allowlisted")

        if not matched:
            return []
        return [
            Signal(
                name="known_good_entity",
                points=self.config.weight("known_good_entity"),
                detail="; ".join(matched),
                from_config=True,
            )
        ]

    def _signal_prior_closures(
        self, incident: Incident, enrichment: Enrichment
    ) -> List[Signal]:
        if not enrichment.prior_closures:
            return []
        entities = sorted({c.entity for c in enrichment.prior_closures if c.entity})
        numbers = sorted({c.incident_number for c in enrichment.prior_closures})[:5]
        detail = (
            f"{len(enrichment.prior_closures)} prior incident(s) from this rule with the "
            f"same entit{'y' if len(entities) == 1 else 'ies'} "
            f"({', '.join(entities[:3])}) were closed as false/benign positive "
            f"(e.g. #{', #'.join(str(n) for n in numbers[:3])})"
        )
        return [
            Signal(
                name="prior_fp_closure",
                points=self.config.weight("prior_fp_closure"),
                detail=detail,
            )
        ]

    def _signal_rule_history(
        self, incident: Incident, enrichment: Enrichment
    ) -> List[Signal]:
        history = enrichment.rule_history
        if history is None:
            return []
        min_closed = int(self.config.scoring.get("min_closed_for_history", 5))
        if history.closed < min_closed:
            return []

        fp_rate = history.fp_rate
        detail_base = (
            f"rule {history.rule_name!r}: {history.closed} closed in the lookback window, "
            f"{history.false_positive} FP / {history.benign_positive} BTP / "
            f"{history.true_positive} TP"
        )
        if fp_rate >= 0.8:
            return [
                Signal(
                    name="rule_fp_rate_high",
                    points=self.config.weight("rule_fp_rate_high"),
                    detail=f"{fp_rate:.0%} historical non-actionable rate - {detail_base}",
                )
            ]
        if fp_rate >= 0.5:
            return [
                Signal(
                    name="rule_fp_rate_moderate",
                    points=self.config.weight("rule_fp_rate_moderate"),
                    detail=f"{fp_rate:.0%} historical non-actionable rate - {detail_base}",
                )
            ]
        if history.tp_rate >= 0.5 and history.closed >= min_closed * 2:
            return [
                Signal(
                    name="rule_tp_rate_high",
                    points=self.config.weight("rule_tp_rate_high"),
                    detail=(
                        f"{history.tp_rate:.0%} of closed incidents from this rule were "
                        f"true positives - {detail_base}"
                    ),
                )
            ]
        return []

    def _signal_threat_intel(
        self, incident: Incident, enrichment: Enrichment
    ) -> List[Signal]:
        if not enrichment.threat_intel:
            return []
        hits = enrichment.threat_intel
        described = ", ".join(
            f"{hit.entity} ({hit.threat_type or 'unclassified'})" for hit in hits[:3]
        )
        return [
            Signal(
                name="threat_intel_match",
                points=self.config.weight("threat_intel_match"),
                detail=f"{len(hits)} entit{'y' if len(hits) == 1 else 'ies'} matched threat intel: {described}",
            )
        ]

    def _signal_related_incidents(
        self, incident: Incident, enrichment: Enrichment
    ) -> List[Signal]:
        if not enrichment.related_incidents:
            return []
        related = enrichment.related_incidents
        numbers = ", ".join(f"#{r.incident_number}" for r in related[:5])
        shared = sorted({e for r in related for e in r.shared_entities})[:4]
        return [
            Signal(
                name="related_open_incidents",
                points=self.config.weight("related_open_incidents"),
                detail=(
                    f"{len(related)} other open incident(s) share entities "
                    f"({', '.join(shared)}): {numbers}"
                ),
            )
        ]

    def _signal_high_value_asset(
        self, incident: Incident, enrichment: Enrichment
    ) -> List[Signal]:
        hits: List[str] = []
        for value in incident.entity_values(EntityKind.HOST):
            if _regex_any(value, self.config.high_value_hosts):
                hits.append(f"host {value}")
        for value in incident.entity_values(EntityKind.ACCOUNT):
            if _regex_any(value, self.config.high_value_accounts):
                hits.append(f"account {value}")
        if not hits:
            return []
        return [
            Signal(
                name="high_value_asset",
                points=self.config.weight("high_value_asset"),
                detail="touches high-value assets: " + ", ".join(hits[:4]),
                from_config=True,
            )
        ]

    def _signal_multi_tactic(
        self, incident: Incident, enrichment: Enrichment
    ) -> List[Signal]:
        tactics = incident.tactics
        if len(tactics) < 2:
            return []
        return [
            Signal(
                name="multi_tactic",
                points=self.config.weight("multi_tactic"),
                detail=f"alerts span {len(tactics)} MITRE tactics: {', '.join(tactics[:5])}",
            )
        ]

    def _signal_alert_volume(
        self, incident: Incident, enrichment: Enrichment
    ) -> List[Signal]:
        threshold = int(self.config.scoring.get("many_alerts_min", 5))
        if incident.alert_count < threshold:
            return []
        return [
            Signal(
                name="many_alerts",
                points=self.config.weight("many_alerts"),
                detail=f"{incident.alert_count} alerts grouped into this incident",
            )
        ]

    def _signal_service_account(
        self, incident: Incident, enrichment: Enrichment
    ) -> List[Signal]:
        accounts = incident.entity_values(EntityKind.ACCOUNT)
        if not accounts:
            return []
        service = [a for a in accounts if _regex_any(a, self.config.service_account_patterns)]
        if not service or len(service) != len(accounts):
            return []
        return [
            Signal(
                name="service_account",
                points=self.config.weight("service_account"),
                detail=(
                    "all involved accounts look like service/machine accounts: "
                    + ", ".join(service[:3])
                ),
                # Deliberately not from_config: this matches a shipped naming
                # convention, not an operator assertion about these accounts, so
                # it must not buy the config-certainty bonus.
                from_config=False,
            )
        ]

    def _signal_ip_disposition(
        self, incident: Incident, enrichment: Enrichment
    ) -> List[Signal]:
        ips = incident.entities_of(EntityKind.IP)
        if not ips:
            return []
        if all(entity.is_private_ip for entity in ips):
            return [
                Signal(
                    name="internal_only_ips",
                    points=self.config.weight("internal_only_ips"),
                    detail=f"all {len(ips)} IP entities are internal/non-routable",
                )
            ]
        return []

    def _signal_prevalence(
        self, incident: Incident, enrichment: Enrichment
    ) -> List[Signal]:
        """Entities the workspace sees constantly are probably infrastructure.

        Entities it has never seen, and that are externally routable, are the
        opposite. An entity with no prevalence row is treated as unknown rather
        than as rare, because the query may simply not cover the right table.
        """
        signals: List[Signal] = []
        min_days = int(self.config.scoring.get("common_entity_min_days", 10))
        prevalence = {**enrichment.ip_prevalence, **enrichment.account_prevalence}
        if not prevalence:
            return signals

        common = [p for p in prevalence.values() if p.distinct_days >= min_days]
        if common and len(common) == len(prevalence):
            signals.append(
                Signal(
                    name="entity_very_common",
                    points=self.config.weight("entity_very_common"),
                    detail=(
                        "every enriched entity is routine in this workspace ("
                        + ", ".join(
                            f"{p.entity}: {p.events} events over {p.distinct_days}d"
                            for p in common[:3]
                        )
                        + ")"
                    ),
                )
            )

        # Rare + external is the interesting combination.
        if "ip_prevalence" in enrichment.completed:
            external = [e for e in incident.entities_of(EntityKind.IP) if not e.is_private_ip]
            rare = [
                entity
                for entity in external
                if enrichment.ip_prevalence.get(entity.normalized) is None
                or enrichment.ip_prevalence[entity.normalized].events == 0
            ]
            if rare:
                signals.append(
                    Signal(
                        name="rare_external_ip",
                        points=self.config.weight("rare_external_ip"),
                        detail=(
                            f"{len(rare)} external IP(s) with no prior history in the "
                            f"workspace: {', '.join(e.value for e in rare[:3])}"
                        ),
                    )
                )
        return signals

    def _signal_off_hours(self, incident: Incident, enrichment: Enrichment) -> List[Signal]:
        settings = self.config.business_hours
        if not settings.get("enabled", True):
            return []
        local = _to_local(incident.activity_time, settings.get("timezone", "UTC"))
        workdays = set(settings.get("workdays", [0, 1, 2, 3, 4]))
        start = int(settings.get("start_hour", 7))
        end = int(settings.get("end_hour", 19))

        in_hours = local.weekday() in workdays and start <= local.hour < end
        if in_hours:
            return []
        return [
            Signal(
                name="off_hours",
                points=self.config.weight("off_hours"),
                detail=(
                    f"activity at {local.strftime('%Y-%m-%d %H:%M %Z')} falls outside "
                    f"business hours ({start:02d}:00-{end:02d}:00)"
                ),
            )
        ]


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return SEVERITY_ORDER.index("Medium")


def _regex_any(value: str, patterns: Sequence[re.Pattern]) -> bool:
    return any(pattern.search(value) for pattern in patterns)


def matches_any(value: str, patterns: Sequence[str]) -> bool:
    """Case-insensitive regex match against raw pattern strings."""
    for pattern in patterns:
        try:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        except re.error:
            # Config compilation already validated these; a bad one here means
            # the pattern came from somewhere else. Fall back to substring.
            if pattern.lower() in value.lower():
                return True
    return False


def _ip_in_networks(value: str, networks: Sequence[object]) -> bool:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    for network in networks:
        try:
            if address in network:  # type: ignore[operator]
                return True
        except TypeError:
            # IPv4 address against an IPv6 network (or vice versa).
            continue
    return False


def _ip_in_any(value: str, ranges: Sequence[str]) -> bool:
    networks = []
    for entry in ranges:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue
    return _ip_in_networks(value, networks)


def _to_local(moment: datetime, timezone_name: str) -> datetime:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    try:
        return moment.astimezone(ZoneInfo(timezone_name))
    except (ZoneInfoNotFoundError, ValueError, KeyError):
        logger.warning("Unknown timezone %r, falling back to UTC", timezone_name)
        return moment.astimezone(timezone.utc)


__all__ = ["RuleEngine", "Entity", "Disposition", "matches_any"]
