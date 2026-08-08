"""Tests for the KQL enrichment layer.

These assert on query *shape* rather than results, because the shape is what
determines correctness against a real workspace: the arg_max dedupe on
SecurityIncident, the isfuzzy union for optional tables, and JSON-escaped
interpolation of entity values.
"""

from __future__ import annotations

import pytest
from conftest import FakeSentinelClient, account, host, ip, make_config, make_incident

from triage.enrichment import Enricher
from triage.models import EntityKind
from triage.sentinel import kql_literal, kql_string_list


def run(client, incident, config=None):
    config = config or make_config()
    return Enricher(client, config).enrich(incident)


# --------------------------------------------------------------------------- #
# Query correctness
# --------------------------------------------------------------------------- #


def test_security_incident_queries_dedupe_with_arg_max():
    """SecurityIncident holds one row per update; counting raw rows inflates."""
    client = FakeSentinelClient()
    incident = make_incident(entities=[ip("10.0.0.1")])
    run(client, incident)

    incident_queries = [q for q in client.queries if "SecurityIncident" in q]
    assert incident_queries, "expected at least one SecurityIncident query"
    for query in incident_queries:
        assert "arg_max(" in query
        assert "by IncidentNumber" in query


def test_rule_history_uses_indexed_prefilter_then_exact_match():
    client = FakeSentinelClient()
    run(client, make_incident(rule_names=["Suspicious sign-in"]))

    history = next(q for q in client.queries if "FalsePositive = countif" in q)
    # `has` hits the term index; array_index_of then rejects partial matches.
    assert "AlertRuleNames has ruleName" in history
    assert "array_index_of(AlertRuleNames, ruleName) >= 0" in history
    assert 'Status == "Closed"' in history


def test_optional_tables_are_referenced_with_isfuzzy():
    """A workspace missing a table must yield no rows, not a failed query."""
    client = FakeSentinelClient()
    incident = make_incident(entities=[ip("8.8.8.8"), account("alice@corp.example")])
    run(client, incident)

    union_queries = [q for q in client.queries if "union" in q]
    assert union_queries
    for query in union_queries:
        assert "union isfuzzy=true" in query


def test_prevalence_filters_before_projecting():
    """Filter early, transform late — the time and value filters precede project."""
    client = FakeSentinelClient()
    run(client, make_incident(entities=[ip("8.8.8.8")]))

    prevalence = next(q for q in client.queries if "DistinctDays = dcount" in q)
    for leg in prevalence.split("("):
        if "TimeGenerated > ago(lookback)" in leg:
            filter_pos = leg.index("TimeGenerated > ago(lookback)")
            project_pos = leg.index("project") if "project" in leg else len(leg)
            assert filter_pos < project_pos


def test_account_prevalence_matches_case_insensitively():
    """Account casing is producer-controlled and inconsistent; IPs are not."""
    client = FakeSentinelClient()
    run(client, make_incident(entities=[account("Alice@corp.example"), ip("8.8.8.8")]))

    account_query = next(
        q for q in client.queries if "UserPrincipalName" in q and "DistinctDays" in q
    )
    assert "in~ (targets)" in account_query

    ip_query = next(q for q in client.queries if "SourceIP" in q and "DistinctDays" in q)
    assert "in (targets)" in ip_query
    assert "in~ (targets)" not in ip_query


def test_threat_intel_covers_both_table_generations():
    client = FakeSentinelClient()
    run(client, make_incident(entities=[ip("8.8.8.8")]))

    ti = next(q for q in client.queries if "ThreatIntel" in q)
    assert "ThreatIntelligenceIndicator" in ti  # legacy
    assert "ThreatIntelIndicators" in ti  # STIX replacement
    assert "ExpiresOn > now()" in ti


def test_threat_intel_uses_case_not_coalesce_for_string_columns():
    """TI tables use empty strings for unset columns, where coalesce misfires."""
    client = FakeSentinelClient()
    run(client, make_incident(entities=[ip("8.8.8.8")]))

    ti = next(q for q in client.queries if "ThreatIntelligenceIndicator" in q)
    assert "isnotempty(NetworkIP)" in ti
    assert "coalesce(NetworkIP" not in ti


def test_related_incidents_excludes_the_current_incident():
    client = FakeSentinelClient()
    run(client, make_incident(number=777, entities=[ip("10.0.0.1")]))

    related = next(q for q in client.queries if "SharedEntities" in q)
    assert "let currentIncident = 777;" in related
    assert "IncidentNumber != currentIncident" in related
    assert 'Status in ("New", "Active")' in related


# --------------------------------------------------------------------------- #
# Interpolation safety
# --------------------------------------------------------------------------- #


def test_entity_values_are_json_escaped_into_the_query():
    """Entity values come from telemetry, so they must never be raw-interpolated."""
    nasty = 'evil");\ndrop table x //'
    client = FakeSentinelClient()
    incident = make_incident(entities=[host(nasty)])
    run(client, incident)

    for query in client.queries:
        if "targets" in query and "dynamic(" in query:
            # The literal quote/newline must not survive into the query body.
            assert 'evil");\ndrop' not in query
            assert "\\n" in query or "evil" not in query


def test_rule_name_with_quotes_is_escaped():
    client = FakeSentinelClient()
    run(client, make_incident(rule_names=['Rule "with" quotes']))

    history = next(q for q in client.queries if "let ruleName" in q)
    assert '\\"with\\"' in history


def test_kql_helpers_escape_correctly():
    assert kql_string_list(["a", 'b"c']) == 'dynamic(["a", "b\\"c"])'
    assert kql_string_list(["", "  ", "x"]) == 'dynamic(["x"])'
    assert kql_literal('say "hi"') == '"say \\"hi\\""'


# --------------------------------------------------------------------------- #
# Failure handling
# --------------------------------------------------------------------------- #


def test_query_failure_is_recorded_not_raised():
    client = FakeSentinelClient()
    client.fail_markers = ["ThreatIntel"]
    enrichment = run(client, make_incident(entities=[ip("8.8.8.8")]))

    assert "threat_intel" in enrichment.failures
    assert "threat_intel" not in enrichment.completed
    assert enrichment.completed, "other queries should still have run"
    assert 0 < enrichment.completeness < 1


def test_completeness_is_zero_when_nothing_ran():
    from triage.models import Enrichment

    assert Enrichment().completeness == 0.0


def test_enrichment_disabled_skips_every_query():
    client = FakeSentinelClient()
    config = make_config(enrichment={"enabled": False})
    enrichment = run(client, make_incident(entities=[ip("8.8.8.8")]), config)

    assert client.queries == []
    assert enrichment.attempted == 0


def test_incident_without_entities_skips_entity_queries():
    client = FakeSentinelClient()
    enrichment = run(client, make_incident(entities=[]))

    assert "rule_history" in enrichment.completed
    assert "related_incidents" not in enrichment.completed
    assert "ip_prevalence" not in enrichment.completed


def test_incident_without_rule_name_skips_history_queries():
    client = FakeSentinelClient()
    enrichment = run(client, make_incident(rule_names=[], alerts=[], entities=[ip("10.0.0.1")]))

    assert "rule_history" not in enrichment.completed
    assert "prior_closures" not in enrichment.completed
    assert "related_incidents" in enrichment.completed


def test_entity_count_is_capped_per_query():
    client = FakeSentinelClient()
    config = make_config(enrichment={"max_entities_per_query": 3})
    incident = make_incident(entities=[ip(f"10.0.0.{i}") for i in range(1, 25)])
    run(client, incident, config)

    prevalence = next(q for q in client.queries if "DistinctDays" in q)
    assert prevalence.count("10.0.0.") == 3


# --------------------------------------------------------------------------- #
# Row parsing
# --------------------------------------------------------------------------- #


def test_rule_history_rows_are_parsed():
    client = FakeSentinelClient(
        {
            "FalsePositive = countif": [
                {
                    "Closed": 40,
                    "FalsePositive": 30,
                    "BenignPositive": 5,
                    "TruePositive": 4,
                    "Undetermined": 1,
                }
            ]
        }
    )
    enrichment = run(client, make_incident())

    history = enrichment.rule_history
    assert history is not None
    assert history.closed == 40
    assert history.fp_rate == pytest.approx(35 / 40)


def test_related_incident_rows_are_parsed():
    client = FakeSentinelClient(
        {
            "SharedEntities": [
                {
                    "IncidentNumber": 900,
                    "Title": "Malware",
                    "Severity": "high",
                    "SharedEntities": ["10.0.0.1"],
                }
            ]
        }
    )
    enrichment = run(client, make_incident(entities=[ip("10.0.0.1")]))

    assert len(enrichment.related_incidents) == 1
    related = enrichment.related_incidents[0]
    assert related.incident_number == 900
    assert related.severity == "High"  # normalized
    assert related.shared_entities == ["10.0.0.1"]


def test_prevalence_rows_are_parsed():
    client = FakeSentinelClient(
        {
            "DistinctDays": [
                {
                    "Value": "8.8.8.8",
                    "Events": 500,
                    "DistinctDays": 12,
                    "FirstSeen": "2026-01-01T00:00:00Z",
                    "LastSeen": "2026-03-01T00:00:00.1234567Z",
                }
            ]
        }
    )
    enrichment = run(client, make_incident(entities=[ip("8.8.8.8")]))

    prevalence = enrichment.ip_prevalence["8.8.8.8"]
    assert prevalence.events == 500
    assert prevalence.distinct_days == 12
    # ARM emits 7 fractional digits, which bare fromisoformat rejects.
    assert prevalence.last_seen is not None
