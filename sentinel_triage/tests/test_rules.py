"""Tests for the deterministic scoring engine.

The two properties that matter most, and are tested first:

* thin evidence can never produce a false-positive verdict;
* every point of the score traces to a named signal.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from conftest import account, host, ip, make_config, make_incident

from triage.models import (
    Alert,
    Disposition,
    Enrichment,
    EntityPrevalence,
    PriorClosure,
    RelatedIncident,
    RuleFpHistory,
    ThreatIntelHit,
)
from triage.rules import RuleEngine


def full_enrichment() -> Enrichment:
    """An enrichment where every query ran, so confidence is not the variable."""
    enrichment = Enrichment()
    for name in (
        "rule_history",
        "prior_closures",
        "related_incidents",
        "threat_intel",
        "ip_prevalence",
    ):
        enrichment.mark_ok(name)
    enrichment.rule_history = RuleFpHistory(rule_name="Suspicious sign-in", closed=0)
    return enrichment


# --------------------------------------------------------------------------- #
# Asymmetric safety
# --------------------------------------------------------------------------- #


def test_no_evidence_never_yields_false_positive(config):
    """A quiet incident with no enrichment must not be called a false positive."""
    incident = make_incident(severity="Informational")
    verdict = RuleEngine(config).evaluate(incident, Enrichment())

    assert verdict.score <= config.thresholds["false_positive_max"]
    assert verdict.confidence < config.thresholds["min_confidence_for_fp"]
    assert verdict.disposition == Disposition.NEEDS_REVIEW
    assert any("confidence" in reason.lower() for reason in verdict.rationale)


def test_failed_enrichment_lowers_confidence_below_the_fp_floor(config):
    """A query that errored must read as unknown, not as clean."""
    incident = make_incident(severity="Low", entities=[ip("10.1.2.3")])

    healthy = full_enrichment()
    healthy.rule_history = RuleFpHistory(
        rule_name="Suspicious sign-in", closed=40, false_positive=38
    )
    good = RuleEngine(config).evaluate(incident, healthy)
    assert good.disposition == Disposition.LIKELY_FALSE_POSITIVE

    broken = Enrichment()
    broken.mark_ok("threat_intel")
    for name in ("rule_history", "prior_closures", "related_incidents"):
        broken.mark_failed(name, "query timed out")
    degraded = RuleEngine(config).evaluate(incident, broken)

    assert degraded.confidence < good.confidence
    assert degraded.disposition == Disposition.NEEDS_REVIEW


def test_escalation_survives_thin_evidence(config):
    """Escalation is the safe direction, so it is not gated on confidence."""
    incident = make_incident(severity="High", entities=[ip("45.33.32.156")])
    enrichment = Enrichment()
    enrichment.mark_ok("threat_intel")
    enrichment.mark_failed("rule_history", "table not found")
    enrichment.threat_intel = [ThreatIntelHit(entity="45.33.32.156", threat_type="C2")]

    verdict = RuleEngine(config).evaluate(incident, enrichment)

    assert verdict.disposition == Disposition.LIKELY_TRUE_POSITIVE
    assert verdict.confidence < 100


# --------------------------------------------------------------------------- #
# Individual signals
# --------------------------------------------------------------------------- #


def test_baseline_tracks_severity(config):
    engine = RuleEngine(config)
    scores = {}
    for severity in ("Informational", "Low", "Medium", "High"):
        incident = make_incident(severity=severity)
        scores[severity] = engine.evaluate(incident, full_enrichment()).score

    assert scores["Informational"] < scores["Low"] < scores["Medium"] < scores["High"]


def test_high_rule_fp_rate_pushes_toward_false_positive(config):
    incident = make_incident(severity="Medium")
    enrichment = full_enrichment()
    enrichment.rule_history = RuleFpHistory(
        rule_name="Suspicious sign-in", closed=50, false_positive=45, true_positive=5
    )

    verdict = RuleEngine(config).evaluate(incident, enrichment)
    names = {s.name for s in verdict.signals}

    assert "rule_fp_rate_high" in names
    assert verdict.score < 45


def test_rule_history_ignored_below_the_sample_floor(config):
    """Three closed incidents is not a rate; it must not move the score."""
    incident = make_incident(severity="Medium")
    enrichment = full_enrichment()
    enrichment.rule_history = RuleFpHistory(
        rule_name="Suspicious sign-in", closed=3, false_positive=3
    )

    verdict = RuleEngine(config).evaluate(incident, enrichment)
    names = {s.name for s in verdict.signals}

    assert "rule_fp_rate_high" not in names
    assert "rule_fp_rate_moderate" not in names


def test_benign_true_positives_count_toward_the_noise_rate():
    """A BTP closed without response is still noise for triage purposes."""
    history = RuleFpHistory(
        rule_name="r", closed=10, false_positive=3, benign_positive=5, true_positive=2
    )
    assert history.fp_rate == pytest.approx(0.8)
    assert history.tp_rate == pytest.approx(0.2)


def test_prior_fp_closure_for_same_entity(config):
    incident = make_incident(severity="Medium", entities=[account("svc-backup@corp.example")])
    enrichment = full_enrichment()
    enrichment.prior_closures = [
        PriorClosure(
            entity="svc-backup@corp.example",
            incident_number=99,
            classification="BenignPositive",
        )
    ]

    verdict = RuleEngine(config).evaluate(incident, enrichment)
    signal = next(s for s in verdict.signals if s.name == "prior_fp_closure")

    assert signal.points < 0
    assert "#99" in signal.detail


def test_related_open_incidents_escalate(config):
    incident = make_incident(severity="Medium", entities=[ip("198.51.100.9")])
    enrichment = full_enrichment()
    enrichment.related_incidents = [
        RelatedIncident(
            incident_number=501,
            title="Malware detected",
            severity="High",
            shared_entities=["198.51.100.9"],
        ),
        RelatedIncident(
            incident_number=502,
            title="Suspicious PowerShell",
            severity="Medium",
            shared_entities=["198.51.100.9"],
        ),
    ]

    verdict = RuleEngine(config).evaluate(incident, enrichment)
    signal = next(s for s in verdict.signals if s.name == "related_open_incidents")

    assert signal.points > 0
    assert "#501" in signal.detail


def test_multi_tactic_escalates(config):
    incident = make_incident(
        severity="Medium",
        alerts=[
            Alert(id="a1", name="Sign-in", tactics=["InitialAccess"]),
            Alert(id="a2", name="Exfil", tactics=["Exfiltration"]),
        ],
    )
    verdict = RuleEngine(config).evaluate(incident, full_enrichment())
    signal = next(s for s in verdict.signals if s.name == "multi_tactic")

    assert signal.points > 0
    assert "2 MITRE tactics" in signal.detail


def test_single_tactic_does_not_fire_multi_tactic(config):
    incident = make_incident(
        severity="Medium",
        alerts=[
            Alert(id="a1", name="Sign-in", tactics=["InitialAccess"]),
            Alert(id="a2", name="Sign-in again", tactics=["InitialAccess"]),
        ],
    )
    verdict = RuleEngine(config).evaluate(incident, full_enrichment())
    assert "multi_tactic" not in {s.name for s in verdict.signals}


def test_internal_only_ips_de_escalate(config):
    incident = make_incident(severity="Medium", entities=[ip("10.0.0.5"), ip("192.168.1.7")])
    verdict = RuleEngine(config).evaluate(incident, full_enrichment())

    assert "internal_only_ips" in {s.name for s in verdict.signals}


def test_one_public_ip_defeats_internal_only(config):
    incident = make_incident(severity="Medium", entities=[ip("10.0.0.5"), ip("8.8.8.8")])
    verdict = RuleEngine(config).evaluate(incident, full_enrichment())

    assert "internal_only_ips" not in {s.name for s in verdict.signals}


@pytest.mark.parametrize(
    "address,private",
    [
        ("10.0.0.1", True),
        ("172.16.5.4", True),
        ("192.168.0.1", True),
        ("127.0.0.1", True),
        ("169.254.1.1", True),
        ("100.64.0.1", True),  # CGNAT
        ("8.8.8.8", False),
        # RFC5737 documentation ranges are not globally routable.
        ("203.0.113.9", True),
        ("198.51.100.4", True),
        ("192.0.2.1", True),
        ("45.33.32.156", False),
        ("fd00::1", True),
        ("2606:4700::1111", False),
        ("not-an-ip", False),
    ],
)
def test_private_ip_classification(address, private):
    from triage.models import Entity, EntityKind

    assert Entity(kind=EntityKind.IP, value=address).is_private_ip is private


def test_known_good_ranges_require_every_ip_to_match():
    config = make_config(known_good={"ip_ranges": ["10.0.0.0/8"]})
    engine = RuleEngine(config)

    all_good = make_incident(severity="Medium", entities=[ip("10.1.1.1"), ip("10.2.2.2")])
    assert "known_good_entity" in {
        s.name for s in engine.evaluate(all_good, full_enrichment()).signals
    }

    one_outside = make_incident(severity="Medium", entities=[ip("10.1.1.1"), ip("8.8.8.8")])
    assert "known_good_entity" not in {
        s.name for s in engine.evaluate(one_outside, full_enrichment()).signals
    }


def test_high_value_asset_escalates():
    config = make_config(high_value_assets={"hosts": [r"^dc\d+"]})
    incident = make_incident(severity="Medium", entities=[host("dc01.corp.example")])

    verdict = RuleEngine(config).evaluate(incident, full_enrichment())
    signal = next(s for s in verdict.signals if s.name == "high_value_asset")

    assert signal.points > 0
    assert signal.from_config


def test_service_account_requires_all_accounts_to_match(config):
    engine = RuleEngine(config)

    all_service = make_incident(
        severity="Medium", entities=[account("svc-sql@corp.example"), account("WKS01$")]
    )
    assert "service_account" in {
        s.name for s in engine.evaluate(all_service, full_enrichment()).signals
    }

    mixed = make_incident(
        severity="Medium", entities=[account("svc-sql@corp.example"), account("alice@corp.example")]
    )
    assert "service_account" not in {
        s.name for s in engine.evaluate(mixed, full_enrichment()).signals
    }


def test_off_hours_escalates(config):
    # 03:00 UTC on a Sunday: outside both the hour window and the workday set.
    incident = make_incident(
        severity="Medium",
        activity_time=datetime(2026, 3, 15, 3, 0, tzinfo=timezone.utc),
    )
    verdict = RuleEngine(config).evaluate(incident, full_enrichment())

    assert "off_hours" in {s.name for s in verdict.signals}


def test_business_hours_respects_configured_timezone():
    """14:00 UTC is mid-afternoon in UTC but 07:00 in Los Angeles — off hours."""
    config = make_config(
        business_hours={"timezone": "America/Los_Angeles", "start_hour": 9, "end_hour": 17}
    )
    # 2026-03-11 is inside US daylight saving, so 14:00Z == 07:00 PDT,
    # comfortably before the 09:00 local start.
    incident = make_incident(
        severity="Medium",
        activity_time=datetime(2026, 3, 11, 14, 0, tzinfo=timezone.utc),
    )
    verdict = RuleEngine(config).evaluate(incident, full_enrichment())

    assert "off_hours" in {s.name for s in verdict.signals}


def test_unknown_timezone_falls_back_to_utc_without_raising():
    config = make_config(business_hours={"timezone": "Mars/Olympus_Mons"})
    incident = make_incident(severity="Medium")
    verdict = RuleEngine(config).evaluate(incident, full_enrichment())

    assert verdict.disposition in set(Disposition)


def test_common_entity_de_escalates(config):
    incident = make_incident(severity="Medium", entities=[ip("192.0.2.50")])
    enrichment = full_enrichment()
    enrichment.ip_prevalence = {
        "192.0.2.50": EntityPrevalence(
            entity="192.0.2.50", events=12000, distinct_days=14
        )
    }

    verdict = RuleEngine(config).evaluate(incident, enrichment)
    assert "entity_very_common" in {s.name for s in verdict.signals}


def test_rare_external_ip_escalates_only_when_the_query_ran(config):
    incident = make_incident(severity="Medium", entities=[ip("45.33.32.156")])

    ran = Enrichment()
    ran.mark_ok("ip_prevalence")
    ran.ip_prevalence = {"45.33.32.156": EntityPrevalence(entity="45.33.32.156", events=0)}
    assert "rare_external_ip" in {
        s.name for s in RuleEngine(config).evaluate(incident, ran).signals
    }

    # Same absence of rows, but the query never ran: absence proves nothing.
    did_not_run = Enrichment()
    did_not_run.mark_failed("ip_prevalence", "timeout")
    assert "rare_external_ip" not in {
        s.name for s in RuleEngine(config).evaluate(incident, did_not_run).signals
    }


def test_many_alerts_escalates(config):
    incident = make_incident(severity="Medium", alert_count=12)
    verdict = RuleEngine(config).evaluate(incident, full_enrichment())

    assert "many_alerts" in {s.name for s in verdict.signals}


# --------------------------------------------------------------------------- #
# Suppressions
# --------------------------------------------------------------------------- #


def test_suppression_forces_false_positive_with_high_confidence():
    config = make_config(
        suppressions=[
            {
                "name": "backup-window-scanner",
                "reason": "Nightly vulnerability scanner, approved by IT ops",
                "rule_names": ["Suspicious sign-in"],
                "entities": {"ip_ranges": ["10.50.0.0/24"]},
            }
        ]
    )
    incident = make_incident(severity="High", entities=[ip("10.50.0.9")])

    verdict = RuleEngine(config).evaluate(incident, full_enrichment())

    assert verdict.disposition == Disposition.LIKELY_FALSE_POSITIVE
    assert verdict.confidence >= 90
    assert any("backup-window-scanner" in reason for reason in verdict.rationale)


def test_suppression_requires_every_declared_condition():
    config = make_config(
        suppressions=[
            {
                "name": "narrow",
                "reason": "only this rule and this range",
                "rule_names": ["Suspicious sign-in"],
                "entities": {"ip_ranges": ["10.50.0.0/24"]},
            }
        ]
    )
    # Right rule, wrong IP.
    wrong_ip = make_incident(severity="High", entities=[ip("10.99.0.9")])
    assert RuleEngine(config).evaluate(wrong_ip, full_enrichment()).disposition != (
        Disposition.LIKELY_FALSE_POSITIVE
    )

    # Right IP, wrong rule.
    wrong_rule = make_incident(
        severity="High", rule_names=["Impossible travel"], entities=[ip("10.50.0.9")]
    )
    assert RuleEngine(config).evaluate(wrong_rule, full_enrichment()).disposition != (
        Disposition.LIKELY_FALSE_POSITIVE
    )


def test_suppression_max_severity_gate():
    config = make_config(
        suppressions=[
            {
                "name": "low-only",
                "reason": "noise, but only when it is low severity",
                "rule_names": ["Suspicious sign-in"],
                "max_severity": "Low",
            }
        ]
    )
    low = make_incident(severity="Low")
    assert RuleEngine(config).evaluate(low, full_enrichment()).disposition == (
        Disposition.LIKELY_FALSE_POSITIVE
    )

    high = make_incident(severity="High")
    assert RuleEngine(config).evaluate(high, full_enrichment()).disposition != (
        Disposition.LIKELY_FALSE_POSITIVE
    )


# --------------------------------------------------------------------------- #
# Determinism and bounds
# --------------------------------------------------------------------------- #


def test_scoring_is_deterministic(config):
    incident = make_incident(
        severity="Medium", entities=[ip("45.33.32.156"), account("alice@corp.example")]
    )
    enrichment = full_enrichment()
    enrichment.threat_intel = [ThreatIntelHit(entity="45.33.32.156", threat_type="C2")]
    engine = RuleEngine(config)

    first = engine.evaluate(incident, enrichment)
    second = engine.evaluate(incident, enrichment)

    assert (first.score, first.confidence, first.disposition) == (
        second.score,
        second.confidence,
        second.disposition,
    )


def test_score_and_confidence_stay_in_range(config):
    engine = RuleEngine(config)
    enrichment = full_enrichment()
    enrichment.threat_intel = [ThreatIntelHit(entity=f"e{i}") for i in range(10)]
    enrichment.related_incidents = [
        RelatedIncident(incident_number=i, title="t", severity="High") for i in range(10)
    ]

    for severity in ("Informational", "Low", "Medium", "High"):
        verdict = engine.evaluate(make_incident(severity=severity), enrichment)
        assert 0 <= verdict.score <= 100
        assert 0 <= verdict.confidence <= 100


def test_every_signal_carries_evidence(config):
    """A signal with no detail is not reviewable, so none may ship without one."""
    incident = make_incident(
        severity="High",
        entities=[ip("45.33.32.156"), account("svc-x@corp.example"), host("dc01")],
        alerts=[
            Alert(id="a1", name="A", tactics=["InitialAccess"]),
            Alert(id="a2", name="B", tactics=["Exfiltration"]),
        ],
        alert_count=9,
    )
    enrichment = full_enrichment()
    enrichment.rule_history = RuleFpHistory(rule_name="r", closed=30, false_positive=28)
    enrichment.threat_intel = [ThreatIntelHit(entity="45.33.32.156", threat_type="C2")]

    verdict = RuleEngine(config).evaluate(incident, enrichment)

    assert verdict.signals
    for signal in verdict.signals:
        assert signal.detail.strip(), f"signal {signal.name} has no evidence"
        assert signal.name


def test_suggested_severity_is_omitted_when_it_matches(config):
    incident = make_incident(severity="Medium")
    verdict = RuleEngine(config).evaluate(incident, full_enrichment())

    if verdict.suggested_severity is not None:
        assert verdict.suggested_severity != incident.severity
