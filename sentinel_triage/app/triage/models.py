"""Domain models for Sentinel incident triage.

Everything the triage engine reasons about is a plain dataclass so the rule
engine can be unit tested without touching Azure.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional

# Sentinel severities, ordered low to high.
SEVERITY_ORDER = ["Informational", "Low", "Medium", "High"]


class Disposition(str, Enum):
    """The triage verdict. Ordered from most benign to most malicious."""

    LIKELY_FALSE_POSITIVE = "LikelyFalsePositive"
    NEEDS_REVIEW = "NeedsReview"
    LIKELY_TRUE_POSITIVE = "LikelyTruePositive"


class EntityKind(str, Enum):
    IP = "Ip"
    ACCOUNT = "Account"
    HOST = "Host"
    URL = "Url"
    DNS = "DnsResolution"
    FILE_HASH = "FileHash"
    FILE = "File"
    PROCESS = "Process"
    MAILBOX = "Mailbox"
    AZURE_RESOURCE = "AzureResource"
    CLOUD_APPLICATION = "CloudApplication"
    OTHER = "Other"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_arm_time(value: Any) -> Optional[datetime]:
    """Parse the ISO-8601 timestamps ARM returns, tolerating >6 fractional digits.

    ``datetime.fromisoformat`` on Python 3.9-3.10 rejects both the trailing ``Z``
    and 7-digit fractional seconds, which ARM emits routinely.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    text = text.replace("Z", "+00:00")
    # Truncate fractional seconds to microsecond precision.
    text = re.sub(r"\.(\d{6})\d+", r".\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass
class Entity:
    """An entity attached to an incident (IP, account, host, hash, ...)."""

    kind: EntityKind
    value: str
    properties: Dict[str, Any] = field(default_factory=dict)

    @property
    def normalized(self) -> str:
        return self.value.strip().lower()

    @property
    def is_ip(self) -> bool:
        return self.kind == EntityKind.IP

    @property
    def is_private_ip(self) -> bool:
        """True for any address that is not globally routable.

        Covers RFC1918, loopback, link-local, CGNAT (100.64/10), reserved space
        and the RFC5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
        203.0.113.0/24). Traffic to or from any of them is internal or bogus —
        neither is "an external address we should worry about" — so grouping
        them is the behaviour the signals want.
        """
        if not self.is_ip:
            return False
        try:
            addr = ipaddress.ip_address(self.value.strip())
        except ValueError:
            return False
        return not addr.is_global

    def __str__(self) -> str:  # pragma: no cover - display helper
        return f"{self.kind.value}:{self.value}"


@dataclass
class Alert:
    """A single alert rolled up into an incident."""

    id: str
    name: str
    severity: str = "Medium"
    tactics: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    product_name: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    description: Optional[str] = None


@dataclass
class Incident:
    """A Sentinel incident, flattened into the fields triage cares about."""

    # ARM resource id, e.g. /subscriptions/.../incidents/<name>
    arm_id: str
    # The incident's GUID name (used as the id in API paths).
    name: str
    number: int
    title: str
    severity: str = "Medium"
    status: str = "New"
    description: str = ""
    labels: List[str] = field(default_factory=list)
    classification: Optional[str] = None
    classification_reason: Optional[str] = None
    owner: Dict[str, Any] = field(default_factory=dict)
    created_time: Optional[datetime] = None
    last_modified_time: Optional[datetime] = None
    first_activity_time: Optional[datetime] = None
    alert_rule_names: List[str] = field(default_factory=list)
    alert_rule_ids: List[str] = field(default_factory=list)
    alert_count: int = 0
    provider_name: Optional[str] = None
    incident_url: Optional[str] = None
    etag: Optional[str] = None
    alerts: List[Alert] = field(default_factory=list)
    entities: List[Entity] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def tactics(self) -> List[str]:
        """Distinct MITRE tactics across all alerts, preserving first-seen order."""
        seen: List[str] = []
        for alert in self.alerts:
            for tactic in alert.tactics:
                if tactic not in seen:
                    seen.append(tactic)
        return seen

    @property
    def techniques(self) -> List[str]:
        seen: List[str] = []
        for alert in self.alerts:
            for technique in alert.techniques:
                if technique not in seen:
                    seen.append(technique)
        return seen

    @property
    def primary_rule_name(self) -> Optional[str]:
        return self.alert_rule_names[0] if self.alert_rule_names else None

    def entities_of(self, *kinds: EntityKind) -> List[Entity]:
        wanted = set(kinds)
        return [e for e in self.entities if e.kind in wanted]

    def entity_values(self, *kinds: EntityKind) -> List[str]:
        """Distinct, lowercased entity values for the given kinds."""
        seen: List[str] = []
        for entity in self.entities_of(*kinds) if kinds else self.entities:
            value = entity.normalized
            if value and value not in seen:
                seen.append(value)
        return seen

    @property
    def activity_time(self) -> datetime:
        """Best available "when did this happen" timestamp."""
        for candidate in (self.first_activity_time, self.created_time):
            if candidate is not None:
                return candidate
        return _utcnow()


@dataclass
class RuleFpHistory:
    """Historical disposition of closed incidents from the same analytics rule."""

    rule_name: str
    closed: int = 0
    false_positive: int = 0
    benign_positive: int = 0
    true_positive: int = 0
    undetermined: int = 0

    @property
    def fp_rate(self) -> float:
        """Share of closed incidents dispositioned as not-actionable.

        Benign true positives count toward the noise rate: the activity was real
        but the analyst still closed it without response.
        """
        if self.closed <= 0:
            return 0.0
        return (self.false_positive + self.benign_positive) / self.closed

    @property
    def tp_rate(self) -> float:
        if self.closed <= 0:
            return 0.0
        return self.true_positive / self.closed


@dataclass
class EntityPrevalence:
    """How often an entity has been observed in the workspace."""

    entity: str
    events: int = 0
    distinct_days: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


@dataclass
class PriorClosure:
    """A previously closed incident that shared this rule and entity."""

    entity: str
    incident_number: int
    classification: str
    closed_time: Optional[datetime] = None
    reason: Optional[str] = None


@dataclass
class RelatedIncident:
    """An open incident sharing at least one entity with the current one."""

    incident_number: int
    title: str
    severity: str
    shared_entities: List[str] = field(default_factory=list)


@dataclass
class ThreatIntelHit:
    entity: str
    threat_type: Optional[str] = None
    confidence: Optional[float] = None
    source: Optional[str] = None
    description: Optional[str] = None


@dataclass
class Enrichment:
    """Everything the enrichment stage managed to gather.

    ``failures`` is load bearing: a signal that could not be evaluated must lower
    the confidence of the verdict rather than silently reading as "nothing found".
    """

    rule_history: Optional[RuleFpHistory] = None
    prior_closures: List[PriorClosure] = field(default_factory=list)
    related_incidents: List[RelatedIncident] = field(default_factory=list)
    ip_prevalence: Dict[str, EntityPrevalence] = field(default_factory=dict)
    account_prevalence: Dict[str, EntityPrevalence] = field(default_factory=dict)
    threat_intel: List[ThreatIntelHit] = field(default_factory=list)
    # Name of each enrichment query that ran successfully.
    completed: List[str] = field(default_factory=list)
    # Name -> error message for queries that failed or timed out.
    failures: Dict[str, str] = field(default_factory=dict)

    def mark_ok(self, name: str) -> None:
        if name not in self.completed:
            self.completed.append(name)

    def mark_failed(self, name: str, error: str) -> None:
        self.failures[name] = error

    @property
    def attempted(self) -> int:
        return len(self.completed) + len(self.failures)

    @property
    def completeness(self) -> float:
        """Fraction of attempted enrichment queries that returned data.

        Returns 0.0 when nothing was attempted, which deliberately reads as
        "no evidence" rather than "perfect evidence".
        """
        if self.attempted == 0:
            return 0.0
        return len(self.completed) / self.attempted


@dataclass
class Signal:
    """One contributing factor in the score, with its evidence."""

    name: str
    points: float
    detail: str
    # Signals that fired purely from configuration (allowlists, suppressions)
    # rather than from observed data.
    from_config: bool = False

    @property
    def direction(self) -> str:
        if self.points > 0:
            return "escalating"
        if self.points < 0:
            return "de-escalating"
        return "neutral"


@dataclass
class Verdict:
    """The triage outcome."""

    disposition: Disposition
    # 0 (certainly benign) to 100 (certainly malicious).
    score: float
    # 0-100, how much the evidence supports the score.
    confidence: float
    signals: List[Signal] = field(default_factory=list)
    # Human-readable reasons the disposition landed where it did.
    rationale: List[str] = field(default_factory=list)
    # Optional narrative from the LLM layer; never affects score.
    narrative: Optional[str] = None
    # Set when the LLM disagreed with the rule engine.
    llm_dissent: Optional[str] = None
    suggested_severity: Optional[str] = None

    @property
    def is_actionable_fp(self) -> bool:
        return self.disposition == Disposition.LIKELY_FALSE_POSITIVE

    def top_signals(self, limit: int = 8) -> List[Signal]:
        """Signals ordered by absolute impact.

        Zero-point signals are kept: a suppression carries no weight because it
        overrides the score outright, and hiding it would leave the single most
        important reason for the verdict out of the comment.
        """
        return sorted(self.signals, key=lambda s: abs(s.points), reverse=True)[:limit]


@dataclass
class TriageResult:
    """What the agent did to one incident."""

    incident: Incident
    enrichment: Enrichment
    verdict: Verdict
    actions_taken: List[str] = field(default_factory=list)
    actions_skipped: List[str] = field(default_factory=list)
    error: Optional[str] = None
    dry_run: bool = False

    def summary(self) -> str:
        return (
            f"#{self.incident.number} {self.incident.title!r} -> "
            f"{self.verdict.disposition.value} "
            f"(score {self.verdict.score:.0f}, confidence {self.verdict.confidence:.0f})"
        )


def normalize_severity(value: Any) -> str:
    """Map an arbitrary severity string onto Sentinel's four levels."""
    if not value:
        return "Medium"
    text = str(value).strip().lower()
    for level in SEVERITY_ORDER:
        if level.lower() == text:
            return level
    aliases = {
        "info": "Informational",
        "informational": "Informational",
        "critical": "High",
        "sev0": "High",
        "sev1": "High",
        "sev2": "Medium",
        "sev3": "Low",
    }
    return aliases.get(text, "Medium")


def dedupe(values: Iterable[str]) -> List[str]:
    """Order-preserving dedupe of non-empty strings."""
    seen: List[str] = []
    marker = set()
    for value in values:
        if not value:
            continue
        if value not in marker:
            marker.add(value)
            seen.append(value)
    return seen
