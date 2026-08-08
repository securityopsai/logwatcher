"""Tests for configuration validation and Sentinel payload parsing."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import timezone

import pytest

from triage.config import (
    DEFAULT_CONFIG,
    ConfigError,
    WorkspaceSettings,
    compile_config,
    load_config,
)
from triage.models import EntityKind, normalize_severity, parse_arm_time
from triage.sentinel import (
    incident_name_from_arm_id,
    parse_alert,
    parse_entity,
    parse_incident,
    rows_from_logs_response,
)

# --------------------------------------------------------------------------- #
# Config validation
# --------------------------------------------------------------------------- #


def test_defaults_are_a_valid_configuration():
    config = compile_config({})
    assert config.actions["dry_run"] is False
    assert config.actions["auto_close"]["enabled"] is False
    assert config.llm["provider"] == "none"


def test_partial_override_merges_rather_than_replacing():
    config = compile_config({"scoring": {"thresholds": {"false_positive_max": 25}}})

    assert config.thresholds["false_positive_max"] == 25
    # Untouched sibling keys survive the merge.
    assert config.thresholds["true_positive_min"] == (
        DEFAULT_CONFIG["scoring"]["thresholds"]["true_positive_min"]
    )


def test_lists_replace_wholesale_so_defaults_can_be_emptied():
    config = compile_config({"enrichment": {"ip_prevalence_sources": []}})
    assert config.enrichment["ip_prevalence_sources"] == []


def test_overlapping_thresholds_are_rejected():
    with pytest.raises(ConfigError, match="lower than true_positive_min"):
        compile_config(
            {"scoring": {"thresholds": {"false_positive_max": 80, "true_positive_min": 70}}}
        )


def test_invalid_business_hours_are_rejected():
    with pytest.raises(ConfigError, match="earlier than end_hour"):
        compile_config({"business_hours": {"start_hour": 20, "end_hour": 8}})


def test_bad_regex_is_rejected_at_load_time():
    with pytest.raises(ConfigError, match="Invalid regex"):
        compile_config({"known_good": {"accounts": ["([unclosed"]}})


def test_bad_cidr_is_rejected_at_load_time():
    with pytest.raises(ConfigError, match="Invalid IP range"):
        compile_config({"known_good": {"ip_ranges": ["10.0.0.0/99"]}})


def test_lookback_must_be_a_kql_timespan():
    """Lookbacks are interpolated into KQL, so anything else is a defect."""
    with pytest.raises(ConfigError, match="KQL timespan"):
        compile_config({"enrichment": {"lookback": {"rule_history": "90 days"}}})
    with pytest.raises(ConfigError, match="KQL timespan"):
        compile_config({"enrichment": {"lookback": {"rule_history": "1d) | evil"}}})


def test_polling_lookback_is_validated_too():
    with pytest.raises(ConfigError, match="KQL timespan"):
        compile_config({"polling": {"lookback": "yesterday"}})


def test_prevalence_source_identifiers_are_constrained():
    """Table and column names reach KQL unquoted, so the schema pins them down."""
    jsonschema = pytest.importorskip("jsonschema")
    with pytest.raises(ConfigError):
        compile_config(
            {
                "enrichment": {
                    "ip_prevalence_sources": [
                        {"table": "T | where 1==1 //", "column": "SourceIP"}
                    ]
                }
            }
        )


def test_unknown_top_level_key_is_rejected():
    pytest.importorskip("jsonschema")
    with pytest.raises(ConfigError):
        compile_config({"totally_unknown_section": {"a": 1}})


def test_suppression_requires_name_and_reason():
    pytest.importorskip("jsonschema")
    with pytest.raises(ConfigError):
        compile_config({"suppressions": [{"rule_names": ["x"]}]})


def test_env_overrides_apply():
    config = load_config(
        env={
            "TRIAGE_DRY_RUN": "true",
            "TRIAGE_AUTO_CLOSE": "yes",
            "TRIAGE_LLM_PROVIDER": "anthropic",
            "TRIAGE_POLL_LOOKBACK": "12h",
        }
    )

    assert config.actions["dry_run"] is True
    assert config.actions["auto_close"]["enabled"] is True
    assert config.llm["provider"] == "anthropic"
    assert config.polling["lookback"] == "12h"


def test_yaml_and_json_config_files_load_identically():
    yaml = pytest.importorskip("yaml")
    payload = {"scoring": {"thresholds": {"false_positive_max": 22}}}

    with tempfile.TemporaryDirectory() as tmp:
        json_path = os.path.join(tmp, "triage.json")
        yaml_path = os.path.join(tmp, "triage.yaml")
        with open(json_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        with open(yaml_path, "w", encoding="utf-8") as handle:
            yaml.safe_dump(payload, handle)

        assert load_config(json_path, env={}).thresholds["false_positive_max"] == 22
        assert load_config(yaml_path, env={}).thresholds["false_positive_max"] == 22


def test_missing_config_file_is_an_error():
    with pytest.raises(ConfigError, match="not found"):
        load_config("/nonexistent/triage.yaml", env={})


# --------------------------------------------------------------------------- #
# Workspace settings
# --------------------------------------------------------------------------- #


def test_workspace_settings_build_the_sentinel_base_path():
    settings = WorkspaceSettings(
        subscription_id="sub", resource_group="rg", workspace_name="ws"
    )
    assert settings.sentinel_base == (
        "/subscriptions/sub/resourceGroups/rg"
        "/providers/Microsoft.OperationalInsights/workspaces/ws"
        "/providers/Microsoft.SecurityInsights"
    )


def test_missing_environment_variables_are_named():
    with pytest.raises(ConfigError, match="SENTINEL_WORKSPACE_NAME"):
        WorkspaceSettings.from_env({"AZURE_SUBSCRIPTION_ID": "s", "SENTINEL_RESOURCE_GROUP": "r"})


# --------------------------------------------------------------------------- #
# Payload parsing
# --------------------------------------------------------------------------- #

ARM_INCIDENT = {
    "id": (
        "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights"
        "/workspaces/ws/providers/Microsoft.SecurityInsights/incidents/abc-123"
    ),
    "name": "abc-123",
    "etag": '"0x8DB"',
    "properties": {
        "incidentNumber": 4242,
        "title": "Suspicious sign-in",
        "severity": "High",
        "status": "New",
        "description": "A sign-in from an unfamiliar location",
        "createdTimeUtc": "2026-03-11T10:00:00.1234567Z",
        "firstActivityTimeUtc": "2026-03-11T09:55:00Z",
        "labels": [{"labelName": "vip", "labelType": "User"}],
        "relatedAnalyticRuleIds": ["/subscriptions/sub/.../alertRules/rule-1"],
        "additionalData": {"alertsCount": 3, "alertProductNames": ["Azure AD Identity Protection"]},
        "incidentUrl": "https://portal.azure.com/#blade/incident",
    },
}


def test_parse_arm_incident():
    incident = parse_incident(ARM_INCIDENT)

    assert incident.number == 4242
    assert incident.name == "abc-123"
    assert incident.severity == "High"
    assert incident.labels == ["vip"]
    assert incident.alert_count == 3
    assert incident.etag == '"0x8DB"'
    assert incident.created_time is not None
    assert incident.created_time.tzinfo is not None


def test_parse_playbook_trigger_body_unwraps_object():
    """The Logic App connector nests the resource one level deeper."""
    incident = parse_incident({"object": ARM_INCIDENT, "workspaceId": "guid"})
    assert incident.number == 4242
    assert incident.name == "abc-123"


def test_seven_digit_fractional_seconds_parse():
    """ARM emits 7 fractional digits, which bare fromisoformat rejects."""
    parsed = parse_arm_time("2026-03-11T10:00:00.1234567Z")
    assert parsed is not None
    assert parsed.tzinfo == timezone.utc
    assert parsed.microsecond == 123456


@pytest.mark.parametrize("value", [None, "", "not a date", 12345])
def test_unparseable_timestamps_return_none(value):
    assert parse_arm_time(value) is None


def test_parse_ip_entity():
    entity = parse_entity({"kind": "Ip", "properties": {"address": "10.0.0.5"}})
    assert entity is not None
    assert entity.kind == EntityKind.IP
    assert entity.value == "10.0.0.5"


def test_account_entity_gains_its_upn_suffix():
    entity = parse_entity(
        {"kind": "Account", "properties": {"accountName": "alice", "upnSuffix": "corp.example"}}
    )
    assert entity is not None
    assert entity.value == "alice@corp.example"


def test_account_entity_with_existing_upn_is_left_alone():
    entity = parse_entity(
        {
            "kind": "Account",
            "properties": {"accountName": "alice@corp.example", "upnSuffix": "corp.example"},
        }
    )
    assert entity is not None
    assert entity.value == "alice@corp.example"


def test_entity_without_a_usable_value_is_dropped():
    assert parse_entity({"kind": "Ip", "properties": {}}) is None
    assert parse_entity({"kind": "Ip"}) is None
    assert parse_entity("not an object") is None


def test_unknown_entity_kind_falls_back_to_other():
    entity = parse_entity({"kind": "Nanoprobe", "properties": {"friendlyName": "x"}})
    assert entity is not None
    assert entity.kind == EntityKind.OTHER


def test_parse_alert_normalizes_severity_and_tactics():
    alert = parse_alert(
        {
            "id": "/alerts/1",
            "properties": {
                "alertDisplayName": "Impossible travel",
                "alertSeverity": "informational",
                "tactics": ["InitialAccess"],
                "startTimeUtc": "2026-03-11T09:00:00Z",
            },
        }
    )
    assert alert is not None
    assert alert.severity == "Informational"
    assert alert.tactics == ["InitialAccess"]
    assert alert.start_time is not None


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("High", "High"),
        ("high", "High"),
        ("informational", "Informational"),
        ("info", "Informational"),
        ("critical", "High"),
        ("", "Medium"),
        (None, "Medium"),
        ("nonsense", "Medium"),
    ],
)
def test_severity_normalization(raw, expected):
    assert normalize_severity(raw) == expected


def test_incident_name_extraction_from_arm_id():
    assert incident_name_from_arm_id(ARM_INCIDENT["id"]) == "abc-123"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "/subscriptions/sub/resourceGroups/rg",
        "/subscriptions/sub/providers/Microsoft.SecurityInsights/incidents",
    ],
)
def test_bad_arm_ids_raise(bad):
    with pytest.raises(ValueError):
        incident_name_from_arm_id(bad)


def test_log_analytics_rows_are_zipped_to_dicts():
    payload = {
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": [{"name": "A"}, {"name": "B"}],
                "rows": [[1, "x"], [2, "y"]],
            }
        ]
    }
    assert rows_from_logs_response(payload) == [{"A": 1, "B": "x"}, {"A": 2, "B": "y"}]


def test_empty_log_analytics_response():
    assert rows_from_logs_response({}) == []
    assert rows_from_logs_response({"tables": []}) == []


def test_incident_entity_helpers_dedupe_and_lowercase():
    incident = parse_incident(
        {
            **ARM_INCIDENT,
            "properties": {
                **ARM_INCIDENT["properties"],
                "entities": [
                    {"kind": "Ip", "properties": {"address": "10.0.0.1"}},
                    {"kind": "Ip", "properties": {"address": "10.0.0.1"}},
                    {"kind": "Host", "properties": {"hostName": "WEB01"}},
                ],
            },
        }
    )

    assert incident.entity_values(EntityKind.IP) == ["10.0.0.1"]
    assert incident.entity_values(EntityKind.HOST) == ["web01"]
    assert len(incident.entity_values()) == 2
