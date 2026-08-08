"""What the agent writes back to Sentinel.

Default posture is comment plus labels. Auto-close exists but is gated on five
independent conditions — a global flag, a confidence floor, a score ceiling, an
explicit per-rule allowlist, and the absence of a model dissent — because an
agent that closes incidents by default will eventually close the one that
mattered.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, List, Tuple

from .config import TriageConfig
from .models import Disposition, Enrichment, Incident, TriageResult, Verdict
from .rules import matches_any

logger = logging.getLogger(__name__)

DISPOSITION_LABELS = {
    Disposition.LIKELY_FALSE_POSITIVE: "likely-fp",
    Disposition.NEEDS_REVIEW: "needs-review",
    Disposition.LIKELY_TRUE_POSITIVE: "likely-tp",
}

# Sentinel comment ids are GUID-shaped in the portal but accept any string.
# Deriving one from the incident makes re-runs update the same comment rather
# than stacking duplicates.
COMMENT_NAMESPACE = "sentinel-triage-agent"


def comment_id_for(incident: Incident) -> str:
    digest = hashlib.sha256(f"{COMMENT_NAMESPACE}:{incident.name}".encode()).hexdigest()
    return f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def confidence_band(confidence: float) -> str:
    if confidence >= 80:
        return "high"
    if confidence >= 55:
        return "medium"
    return "low"


def build_labels(config: TriageConfig, verdict: Verdict) -> List[str]:
    prefix = config.actions.get("label_prefix", "triage")
    labels = [f"{prefix}:{DISPOSITION_LABELS[verdict.disposition]}"]
    labels.append(f"{prefix}:confidence-{confidence_band(verdict.confidence)}")
    if verdict.llm_dissent:
        labels.append(f"{prefix}:model-dissent")
    return labels


def has_triage_label(config: TriageConfig, incident: Incident) -> bool:
    """True when this incident already carries a label from this agent."""
    prefix = str(config.actions.get("label_prefix", "triage")) + ":"
    return any(label.startswith(prefix) for label in incident.labels)


def render_comment(
    incident: Incident,
    enrichment: Enrichment,
    verdict: Verdict,
    *,
    dry_run: bool = False,
) -> str:
    """Render the analyst-facing triage comment as Markdown.

    Sentinel renders comment bodies as Markdown, so this is what an analyst
    actually reads. The evidence table is the point: a verdict without its
    supporting signals is not reviewable.
    """
    heading = {
        Disposition.LIKELY_FALSE_POSITIVE: "Likely false positive",
        Disposition.NEEDS_REVIEW: "Needs review",
        Disposition.LIKELY_TRUE_POSITIVE: "Likely true positive",
    }[verdict.disposition]

    lines: List[str] = []
    lines.append(f"## Automated triage — {heading}")
    if dry_run:
        lines.append("")
        lines.append("> **Dry run.** No labels or status changes were applied.")
    lines.append("")
    lines.append(
        f"**Suspicion score:** {verdict.score:.0f}/100  |  "
        f"**Confidence:** {verdict.confidence:.0f}/100 ({confidence_band(verdict.confidence)})"
    )

    if verdict.narrative:
        lines.append("")
        lines.append(verdict.narrative)

    if verdict.llm_dissent:
        lines.append("")
        lines.append(f"> **Model dissent:** {verdict.llm_dissent}")

    signals = verdict.top_signals()
    if signals:
        lines.append("")
        lines.append("### Contributing signals")
        lines.append("")
        lines.append("| Impact | Signal | Evidence |")
        lines.append("| --- | --- | --- |")
        for signal in signals:
            # A zero-point signal is an override rather than a contribution, so
            # label it as one instead of printing a misleading "0".
            impact = f"{signal.points:+g}" if signal.points else "override"
            detail = signal.detail.replace("|", "\\|")
            lines.append(f"| {impact} | `{signal.name}` | {detail} |")

    if verdict.rationale:
        lines.append("")
        lines.append("### How this verdict was reached")
        for reason in verdict.rationale:
            lines.append(f"- {reason}")

    if verdict.suggested_severity:
        lines.append("")
        lines.append(
            f"**Suggested severity:** {verdict.suggested_severity} "
            f"(currently {incident.severity})"
        )

    if enrichment.failures:
        lines.append("")
        lines.append("### Evidence gaps")
        lines.append(
            "These lookups did not complete, so their signals were treated as unknown "
            "rather than clean:"
        )
        for name, error in sorted(enrichment.failures.items()):
            lines.append(f"- `{name}`: {error}")

    lines.append("")
    lines.append("---")
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines.append(
        f"_Sentinel triage agent · {stamp} · "
        f"{len(enrichment.completed)}/{max(enrichment.attempted, 1)} enrichment queries succeeded_"
    )
    return "\n".join(lines)


def auto_close_decision(
    config: TriageConfig, incident: Incident, verdict: Verdict
) -> Tuple[bool, str]:
    """Decide whether this incident is eligible for automatic closure.

    Returns ``(eligible, reason)``; the reason explains the *first* gate that
    failed so the skip is auditable.
    """
    settings = config.actions.get("auto_close", {})
    if not settings.get("enabled", False):
        return False, "auto-close is disabled"
    if verdict.disposition != Disposition.LIKELY_FALSE_POSITIVE:
        return False, f"disposition is {verdict.disposition.value}, not a false positive"
    if verdict.llm_dissent:
        return False, "the narrative model dissented"

    min_confidence = float(settings.get("min_confidence", 85))
    if verdict.confidence < min_confidence:
        return False, f"confidence {verdict.confidence:.0f} is below the {min_confidence:.0f} floor"

    max_score = float(settings.get("max_score", 20))
    if verdict.score > max_score:
        return False, f"score {verdict.score:.0f} is above the {max_score:.0f} ceiling"

    allowed = settings.get("allowed_rules", []) or []
    if not allowed:
        return False, "no rules are on the auto-close allowlist"
    if not incident.alert_rule_names:
        return False, "incident has no analytics rule to match against the allowlist"
    if not any(matches_any(name, allowed) for name in incident.alert_rule_names):
        return False, "none of this incident's rules are on the auto-close allowlist"

    return True, "all auto-close conditions were met"


class ActionExecutor:
    """Applies triage output to the incident."""

    def __init__(self, client: Any, config: TriageConfig) -> None:
        self.client = client
        self.config = config

    @property
    def dry_run(self) -> bool:
        return bool(self.config.actions.get("dry_run", False))

    def apply(self, result: TriageResult) -> TriageResult:
        incident = result.incident
        verdict = result.verdict
        result.dry_run = self.dry_run

        comment = render_comment(incident, result.enrichment, verdict, dry_run=self.dry_run)

        if self.config.actions.get("add_comment", True):
            if self.dry_run:
                result.actions_skipped.append("comment (dry run)")
                logger.info("[dry-run] would comment on #%s:\n%s", incident.number, comment)
            else:
                try:
                    self.client.add_comment(incident.name, comment, comment_id_for(incident))
                    result.actions_taken.append("posted triage comment")
                except Exception as exc:  # noqa: BLE001
                    logger.error("Failed to comment on #%s: %s", incident.number, exc)
                    result.actions_skipped.append(f"comment failed: {exc}")

        eligible, reason = auto_close_decision(self.config, incident, verdict)
        labels = build_labels(self.config, verdict) if self.config.actions.get("add_labels", True) else []

        # Severity is only ever *suggested*, in the comment. Applying it would
        # reorder the analyst's severity queue behind their back, so it is
        # recorded as a deliberate non-action rather than written.
        if (
            self.config.actions.get("suggest_severity", True)
            and verdict.suggested_severity
            and not eligible
        ):
            result.actions_skipped.append(
                f"severity change to {verdict.suggested_severity} (suggested in comment only)"
            )

        if not labels and not eligible:
            return result

        if self.dry_run:
            if labels:
                result.actions_skipped.append(f"labels {labels} (dry run)")
            if eligible:
                result.actions_skipped.append("auto-close (dry run)")
            return result

        close_settings = self.config.actions.get("auto_close", {})
        try:
            self.client.update_incident(
                incident,
                labels=labels or None,
                status="Closed" if eligible else None,
                classification=close_settings.get("classification") if eligible else None,
                classification_reason="InaccurateData" if eligible else None,
                classification_comment=(
                    f"Closed automatically by the Sentinel triage agent: {reason}."
                    if eligible
                    else None
                ),
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to update incident #%s: %s", incident.number, exc)
            result.actions_skipped.append(f"incident update failed: {exc}")
            return result

        if labels:
            result.actions_taken.append(f"applied labels {', '.join(labels)}")
        if eligible:
            result.actions_taken.append(
                f"closed as {close_settings.get('classification', 'BenignPositive')}"
            )
        else:
            result.actions_skipped.append(f"auto-close: {reason}")
        return result
