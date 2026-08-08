"""Tests for the orchestrator and the LLM narrative layer.

The escalate-only dissent rule is the load-bearing property here: a model that
can talk the engine *out* of caring about an incident is a liability, so that
direction is tested explicitly in both directions.
"""

from __future__ import annotations

import pytest
from conftest import FakeSentinelClient, ip, make_config, make_incident

from triage.agent import TriageAgent, duration_to_iso8601, duration_to_seconds
from triage.llm import (
    Narrative,
    NullProvider,
    apply_narrative,
    build_prompt,
    build_provider,
    _parse_response,
)
from triage.models import (
    Disposition,
    Enrichment,
    RuleFpHistory,
    Signal,
    ThreatIntelHit,
    Verdict,
)


class StubProvider:
    """An LLM stand-in with a scripted response."""

    name = "stub"

    def __init__(self, narrative: Narrative) -> None:
        self.narrative = narrative
        self.prompts: list = []

    def generate(self, prompt: str) -> Narrative:
        self.prompts.append(prompt)
        return self.narrative


def verdict(disposition=Disposition.LIKELY_FALSE_POSITIVE, **kwargs) -> Verdict:
    return Verdict(
        disposition=disposition,
        score=kwargs.pop("score", 15.0),
        confidence=kwargs.pop("confidence", 90.0),
        signals=[Signal(name="rule_fp_rate_high", points=-25, detail="92% FP historically")],
        rationale=["baseline"],
        **kwargs,
    )


# --------------------------------------------------------------------------- #
# Escalate-only dissent
# --------------------------------------------------------------------------- #


def test_dissent_raises_a_false_positive_to_needs_review():
    result = apply_narrative(
        verdict(Disposition.LIKELY_FALSE_POSITIVE),
        Narrative(
            text="Looks routine, but the host also appears in an open malware incident.",
            disagrees=True,
            dissent_reason="Host overlaps an active malware incident",
        ),
    )

    assert result.disposition == Disposition.NEEDS_REVIEW
    assert result.llm_dissent == "Host overlaps an active malware incident"
    assert any("Raised to needs-review" in r for r in result.rationale)


def test_dissent_cannot_lower_a_true_positive():
    """There is no code path from dissent to a less serious verdict."""
    result = apply_narrative(
        verdict(Disposition.LIKELY_TRUE_POSITIVE),
        Narrative(text="I think this is benign", disagrees=True, dissent_reason="feels fine"),
    )

    assert result.disposition == Disposition.LIKELY_TRUE_POSITIVE


def test_agreement_never_changes_the_disposition():
    for disposition in Disposition:
        result = apply_narrative(
            verdict(disposition), Narrative(text="Agreed.", disagrees=False)
        )
        assert result.disposition == disposition


def test_dissent_without_a_reason_is_ignored():
    """A bare boolean with no justification is not actionable, so it is dropped."""
    result = apply_narrative(
        verdict(Disposition.LIKELY_FALSE_POSITIVE),
        Narrative(text="ok", disagrees=True, dissent_reason=""),
    )

    assert result.disposition == Disposition.LIKELY_FALSE_POSITIVE
    assert result.llm_dissent is None


def test_llm_error_leaves_the_verdict_untouched():
    original = verdict(Disposition.LIKELY_FALSE_POSITIVE)
    result = apply_narrative(
        original, Narrative(text="", error="Anthropic API error: 529 overloaded")
    )

    assert result.disposition == Disposition.LIKELY_FALSE_POSITIVE
    assert result.narrative is None


def test_next_steps_are_folded_into_the_rationale():
    result = apply_narrative(
        verdict(),
        Narrative(text="ok", next_steps=["Check sign-in logs", "Confirm with the user"]),
    )
    assert any("Suggested next steps" in r for r in result.rationale)


# --------------------------------------------------------------------------- #
# Response parsing
# --------------------------------------------------------------------------- #


def test_parse_valid_response():
    narrative = _parse_response(
        '{"narrative": "n", "next_steps": ["a", "b"], "disagrees": false, '
        '"dissent_reason": ""}',
        "stub",
    )
    assert narrative.text == "n"
    assert narrative.next_steps == ["a", "b"]
    assert narrative.error is None


@pytest.mark.parametrize("payload", ["not json", "", "[1, 2, 3]", "null"])
def test_malformed_responses_become_errors_not_exceptions(payload):
    narrative = _parse_response(payload, "stub")
    assert narrative.error is not None
    assert narrative.text == ""


def test_next_steps_are_capped_and_cleaned():
    narrative = _parse_response(
        '{"narrative": "n", "next_steps": ["a", " ", "b", "c", "d", "e"], '
        '"disagrees": false, "dissent_reason": ""}',
        "stub",
    )
    assert narrative.next_steps == ["a", "b", "c", "d"]


# --------------------------------------------------------------------------- #
# Prompt assembly
# --------------------------------------------------------------------------- #


def test_prompt_includes_evidence_and_names_the_gaps():
    incident = make_incident(severity="High", entities=[ip("10.0.0.9")])
    enrichment = Enrichment()
    enrichment.mark_ok("rule_history")
    enrichment.mark_failed("threat_intel", "table missing")
    enrichment.rule_history = RuleFpHistory(rule_name="r", closed=20, false_positive=18)
    enrichment.threat_intel = [ThreatIntelHit(entity="10.0.0.9", threat_type="C2")]

    prompt = build_prompt(incident, enrichment, verdict())

    assert "Suspicious sign-in from unfamiliar location" in prompt
    assert "10.0.0.9" in prompt
    assert "90%" in prompt  # 18/20 historical FP rate
    assert "Could not evaluate" in prompt
    assert "threat_intel" in prompt
    assert "rule_fp_rate_high" in prompt


def test_prompt_states_when_there_is_no_enrichment():
    prompt = build_prompt(make_incident(), Enrichment(), verdict())
    assert "No enrichment data was available." in prompt


# --------------------------------------------------------------------------- #
# Provider selection
# --------------------------------------------------------------------------- #


def test_default_provider_is_null():
    assert build_provider(make_config()).name == "none"


def test_unknown_provider_degrades_to_null():
    # The enum in the schema blocks unknown providers at load time, so reach
    # past it to prove the runtime guard also holds.
    config = make_config()
    config.raw["llm"]["provider"] = "gpt-5-turbo-max"
    assert build_provider(config).name == "none"


def test_misconfigured_azure_openai_degrades_instead_of_raising():
    config = make_config(llm={"provider": "azure_openai", "model": "", "endpoint": ""})
    assert build_provider(config).name == "none"


def test_null_provider_returns_empty_narrative():
    assert NullProvider().generate("anything").text == ""


# --------------------------------------------------------------------------- #
# Agent orchestration
# --------------------------------------------------------------------------- #


def test_template_narrative_is_used_when_no_llm_is_configured():
    config = make_config(actions={"dry_run": True})
    agent = TriageAgent(FakeSentinelClient(), config)
    result = agent.triage_incident(make_incident(entities=[ip("10.0.0.1")]))

    assert result.verdict.narrative
    assert "strongest factors" in result.verdict.narrative.lower() or (
        "evidence" in result.verdict.narrative.lower()
    )


def test_llm_narrative_replaces_the_template():
    config = make_config(actions={"dry_run": True})
    provider = StubProvider(Narrative(text="A crisp analyst summary.", provider="stub"))
    agent = TriageAgent(FakeSentinelClient(), config, llm=provider)

    result = agent.triage_incident(make_incident())

    assert result.verdict.narrative == "A crisp analyst summary."
    assert provider.prompts, "the provider should have been called"


def test_failed_llm_falls_back_to_the_template():
    config = make_config(actions={"dry_run": True})
    provider = StubProvider(Narrative(text="", error="timeout", provider="stub"))
    agent = TriageAgent(FakeSentinelClient(), config, llm=provider)

    result = agent.triage_incident(make_incident())

    assert result.verdict.narrative, "a narrative is always present"


def test_poll_skips_incidents_that_are_already_triaged():
    config = make_config(actions={"dry_run": True})
    client = FakeSentinelClient()
    client.list_incidents = lambda **kwargs: [  # type: ignore[method-assign]
        make_incident(number=1, labels=["triage:likely-fp"]),
        make_incident(number=2, labels=[]),
    ]
    agent = TriageAgent(client, config)

    results = agent.poll(lookback="4h")

    assert [r.incident.number for r in results] == [2]


def test_poll_can_be_told_not_to_skip():
    config = make_config(actions={"dry_run": True}, polling={"skip_labeled": False})
    client = FakeSentinelClient()
    client.list_incidents = lambda **kwargs: [  # type: ignore[method-assign]
        make_incident(number=1, labels=["triage:likely-fp"])
    ]
    agent = TriageAgent(client, config)

    assert len(agent.poll()) == 1


def test_poll_survives_one_bad_incident():
    """A single failure must not abandon the rest of the sweep."""
    config = make_config(actions={"dry_run": True})
    client = FakeSentinelClient()
    client.list_incidents = lambda **kwargs: [  # type: ignore[method-assign]
        make_incident(number=1),
        make_incident(number=2),
        make_incident(number=3),
    ]
    agent = TriageAgent(client, config)

    calls = {"n": 0}
    original = agent.enricher.enrich

    def flaky(incident):
        calls["n"] += 1
        if incident.number == 2:
            raise RuntimeError("workspace unreachable")
        return original(incident)

    agent.enricher.enrich = flaky  # type: ignore[method-assign]
    results = agent.poll()

    assert [r.incident.number for r in results] == [1, 2, 3]
    failed = next(r for r in results if r.incident.number == 2)
    assert failed.error is not None
    assert failed.verdict.disposition == Disposition.NEEDS_REVIEW
    assert failed.verdict.confidence == 0.0


def test_poll_filter_targets_the_configured_statuses():
    config = make_config(actions={"dry_run": True}, polling={"statuses": ["New"]})
    captured = {}

    client = FakeSentinelClient()

    def capture(**kwargs):
        captured.update(kwargs)
        return []

    client.list_incidents = capture  # type: ignore[method-assign]
    TriageAgent(client, config).poll(lookback="6h")

    assert "properties/status eq 'New'" in captured["odata_filter"]
    assert "properties/createdTimeUtc ge" in captured["odata_filter"]


# --------------------------------------------------------------------------- #
# Duration helpers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "value,seconds", [("30s", 30), ("15m", 900), ("4h", 14400), ("2d", 172800)]
)
def test_duration_parsing(value, seconds):
    assert duration_to_seconds(value) == seconds
    assert duration_to_iso8601(value) == f"PT{seconds}S"


@pytest.mark.parametrize("value", ["", "4", "4 hours", "4w", "-1h"])
def test_bad_durations_raise(value):
    with pytest.raises(ValueError):
        duration_to_seconds(value)


def test_provider_that_raises_does_not_break_triage():
    """A narrative is a nice-to-have; an exception from one must not lose the verdict."""

    class ExplodingProvider:
        name = "exploding"

        def generate(self, prompt: str) -> Narrative:
            raise RuntimeError("connection reset by peer")

    config = make_config(actions={"dry_run": True})
    agent = TriageAgent(FakeSentinelClient(), config, llm=ExplodingProvider())

    result = agent.triage_incident(make_incident())

    assert result.error is None
    assert result.verdict.narrative, "should fall back to the template narrative"


def test_suppression_appears_in_the_rendered_comment():
    """The override is the whole reason for the verdict; it must be visible."""
    from triage.actions import render_comment

    config = make_config(
        actions={"dry_run": True},
        suppressions=[
            {
                "name": "nightly-scan",
                "reason": "Approved scanner",
                # The analytics rule name, not the incident title — they differ.
                "rule_names": ["Suspicious sign-in"],
                "titles": ["unfamiliar location"],
            }
        ],
    )
    agent = TriageAgent(FakeSentinelClient(), config)
    result = agent.triage_incident(make_incident())

    body = render_comment(result.incident, result.enrichment, result.verdict, dry_run=True)
    assert "suppression_rule" in body
    assert "override" in body
    assert "nightly-scan" in body
