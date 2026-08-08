"""Tests for what the agent writes back to Sentinel.

The auto-close gates get the most coverage here: every one of them must be able
to independently stop a closure, because that is the only thing standing between
a scoring bug and a closed intrusion.
"""

from __future__ import annotations

import pytest
from conftest import FakeSentinelClient, ip, make_config, make_incident

from triage.actions import (
    ActionExecutor,
    auto_close_decision,
    build_labels,
    comment_id_for,
    has_triage_label,
    render_comment,
)
from triage.models import Disposition, Enrichment, Signal, TriageResult, Verdict


def make_verdict(
    disposition=Disposition.LIKELY_FALSE_POSITIVE,
    score=12.0,
    confidence=92.0,
    **kwargs,
) -> Verdict:
    return Verdict(
        disposition=disposition,
        score=score,
        confidence=confidence,
        signals=kwargs.pop(
            "signals",
            [Signal(name="rule_fp_rate_high", points=-25, detail="93% historical FP rate")],
        ),
        rationale=kwargs.pop("rationale", ["Score 12 <= 30 with confidence 92."]),
        **kwargs,
    )


def run_actions(config, verdict, incident=None, enrichment=None):
    incident = incident or make_incident()
    client = FakeSentinelClient()
    result = TriageResult(
        incident=incident, enrichment=enrichment or Enrichment(), verdict=verdict
    )
    return client, ActionExecutor(client, config).apply(result)


# --------------------------------------------------------------------------- #
# Auto-close gates
# --------------------------------------------------------------------------- #

AUTO_CLOSE_ON = {
    "actions": {
        "auto_close": {
            "enabled": True,
            "min_confidence": 85,
            "max_score": 20,
            "allowed_rules": ["Suspicious sign-in"],
        }
    }
}


def test_auto_close_is_off_by_default(config):
    eligible, reason = auto_close_decision(config, make_incident(), make_verdict())
    assert eligible is False
    assert "disabled" in reason


def test_auto_close_fires_when_every_gate_passes():
    config = make_config(**AUTO_CLOSE_ON)
    eligible, reason = auto_close_decision(config, make_incident(), make_verdict())

    assert eligible is True
    assert "all auto-close conditions" in reason


@pytest.mark.parametrize(
    "verdict_kwargs,expected_fragment",
    [
        ({"disposition": Disposition.NEEDS_REVIEW}, "not a false positive"),
        ({"disposition": Disposition.LIKELY_TRUE_POSITIVE}, "not a false positive"),
        ({"confidence": 60.0}, "below the 85 floor"),
        ({"score": 45.0}, "above the 20 ceiling"),
    ],
)
def test_each_gate_independently_blocks_closure(verdict_kwargs, expected_fragment):
    config = make_config(**AUTO_CLOSE_ON)
    eligible, reason = auto_close_decision(
        config, make_incident(), make_verdict(**verdict_kwargs)
    )

    assert eligible is False
    assert expected_fragment in reason


def test_empty_allowlist_blocks_closure():
    config = make_config(
        actions={"auto_close": {"enabled": True, "min_confidence": 0, "max_score": 100}}
    )
    eligible, reason = auto_close_decision(config, make_incident(), make_verdict())

    assert eligible is False
    assert "allowlist" in reason


def test_rule_not_on_allowlist_blocks_closure():
    config = make_config(**AUTO_CLOSE_ON)
    incident = make_incident(rule_names=["Impossible travel"])
    eligible, reason = auto_close_decision(config, incident, make_verdict())

    assert eligible is False
    assert "allowlist" in reason


def test_model_dissent_blocks_closure():
    """The LLM can veto a closure even though it cannot cause one."""
    config = make_config(**AUTO_CLOSE_ON)
    verdict = make_verdict(llm_dissent="The account also appears in an unrelated alert")
    eligible, reason = auto_close_decision(config, make_incident(), verdict)

    assert eligible is False
    assert "dissent" in reason


def test_closure_sends_classification_and_reason():
    config = make_config(**AUTO_CLOSE_ON)
    client, result = run_actions(config, make_verdict())

    assert len(client.updates) == 1
    update = client.updates[0]
    assert update["status"] == "Closed"
    assert update["classification"] == "BenignPositive"
    assert "triage agent" in update["classification_comment"]
    assert any("closed as" in action for action in result.actions_taken)


def test_blocked_closure_still_applies_labels_and_records_why():
    config = make_config(**AUTO_CLOSE_ON)
    client, result = run_actions(config, make_verdict(confidence=50.0))

    assert client.updates[0]["status"] is None
    assert any("applied labels" in a for a in result.actions_taken)
    assert any("auto-close:" in a for a in result.actions_skipped)


# --------------------------------------------------------------------------- #
# Dry run
# --------------------------------------------------------------------------- #


def test_dry_run_writes_nothing():
    config = make_config(actions={"dry_run": True, **AUTO_CLOSE_ON["actions"]})
    client, result = run_actions(config, make_verdict())

    assert client.comments == []
    assert client.updates == []
    assert result.dry_run is True
    assert len(result.actions_taken) == 0
    assert any("dry run" in a for a in result.actions_skipped)


def test_dry_run_is_marked_in_the_comment_body():
    incident = make_incident()
    body = render_comment(incident, Enrichment(), make_verdict(), dry_run=True)
    assert "Dry run" in body


# --------------------------------------------------------------------------- #
# Labels and idempotency
# --------------------------------------------------------------------------- #


def test_labels_encode_disposition_and_confidence(config):
    labels = build_labels(config, make_verdict(confidence=92.0))
    assert "triage:likely-fp" in labels
    assert "triage:confidence-high" in labels


def test_dissent_gets_its_own_label(config):
    labels = build_labels(config, make_verdict(llm_dissent="looks worse than scored"))
    assert "triage:model-dissent" in labels


def test_custom_label_prefix_is_honoured():
    config = make_config(actions={"label_prefix": "soc-bot"})
    labels = build_labels(config, make_verdict())
    assert all(label.startswith("soc-bot:") for label in labels)


def test_has_triage_label_detects_prior_runs(config):
    assert has_triage_label(config, make_incident(labels=["triage:likely-fp"])) is True
    assert has_triage_label(config, make_incident(labels=["customer-escalation"])) is False
    assert has_triage_label(config, make_incident(labels=[])) is False


def test_comment_id_is_stable_per_incident_and_unique_across_them():
    """Re-running must update one comment, not stack a new one each time."""
    a = make_incident(number=1)
    b = make_incident(number=2)

    assert comment_id_for(a) == comment_id_for(a)
    assert comment_id_for(a) != comment_id_for(b)
    # The Sentinel portal expects a GUID-shaped id.
    assert len(comment_id_for(a).split("-")) == 5


def test_existing_labels_are_preserved_on_update():
    config = make_config(**AUTO_CLOSE_ON)
    incident = make_incident(labels=["customer-escalation"])
    client = FakeSentinelClient()
    ActionExecutor(client, config).apply(
        TriageResult(incident=incident, enrichment=Enrichment(), verdict=make_verdict())
    )

    # update_incident merges with incident.labels; the executor passes only new ones.
    assert "customer-escalation" not in client.updates[0]["labels"]
    assert incident.labels == ["customer-escalation"]


# --------------------------------------------------------------------------- #
# Comment rendering
# --------------------------------------------------------------------------- #


def test_comment_contains_verdict_signals_and_evidence(config):
    incident = make_incident(entities=[ip("10.0.0.1")])
    verdict = make_verdict()
    body = render_comment(incident, Enrichment(), verdict)

    assert "Likely false positive" in body
    assert "12/100" in body
    assert "rule_fp_rate_high" in body
    assert "93% historical FP rate" in body
    assert "| Impact | Signal | Evidence |" in body


def test_comment_reports_evidence_gaps(config):
    enrichment = Enrichment()
    enrichment.mark_ok("rule_history")
    enrichment.mark_failed("threat_intel", "table ThreatIntelIndicators not found")
    body = render_comment(make_incident(), enrichment, make_verdict())

    assert "Evidence gaps" in body
    assert "threat_intel" in body
    assert "1/2 enrichment queries succeeded" in body


def test_comment_escapes_pipes_so_the_table_survives(config):
    verdict = make_verdict(
        signals=[Signal(name="s", points=-5, detail="value a|b|c breaks tables")]
    )
    body = render_comment(make_incident(), Enrichment(), verdict)

    row = next(line for line in body.splitlines() if "`s`" in line)
    assert "a\\|b\\|c" in row
    # Escaped pipes still contain a "|" character, so count only the delimiters
    # a Markdown renderer would act on: 4 of them for a 3-cell row.
    assert row.replace("\\|", "").count("|") == 4


def test_comment_surfaces_model_dissent(config):
    verdict = make_verdict(llm_dissent="Same host appears in an active malware incident")
    body = render_comment(make_incident(), Enrichment(), verdict)

    assert "Model dissent" in body
    assert "active malware incident" in body


def test_comment_failure_does_not_abort_labels(monkeypatch):
    """A failed comment must not take the labels down with it."""
    config = make_config(**AUTO_CLOSE_ON)
    client = FakeSentinelClient()

    def boom(*args, **kwargs):
        raise RuntimeError("429 too many requests")

    client.add_comment = boom
    result = ActionExecutor(client, config).apply(
        TriageResult(incident=make_incident(), enrichment=Enrichment(), verdict=make_verdict())
    )

    assert any("comment failed" in a for a in result.actions_skipped)
    assert client.updates, "the incident update should still have been attempted"
