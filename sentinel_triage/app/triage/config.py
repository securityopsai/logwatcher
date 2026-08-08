"""Configuration loading, validation and defaults for the triage agent.

Config comes from a YAML (or JSON) file; anything deployment-specific can be
overridden by environment variables so the same file works locally and in the
Function App.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:  # PyYAML is optional: JSON config works without it.
    import yaml
except ImportError:  # pragma: no cover - exercised only in minimal installs
    yaml = None

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None


class ConfigError(ValueError):
    """Raised when the configuration is missing or invalid."""


# --------------------------------------------------------------------------- #
# Defaults
# --------------------------------------------------------------------------- #

DEFAULT_CONFIG: Dict[str, Any] = {
    "version": 1,
    "scoring": {
        "baseline_by_severity": {
            "Informational": 10,
            "Low": 25,
            "Medium": 45,
            "High": 65,
        },
        "thresholds": {
            "false_positive_max": 30,
            "true_positive_min": 70,
            "min_confidence_for_fp": 60,
        },
        "weights": {
            # De-escalating (negative) signals
            "known_good_entity": -30,
            "prior_fp_closure": -30,
            "rule_fp_rate_high": -25,
            "rule_fp_rate_moderate": -12,
            "entity_very_common": -10,
            "service_account": -8,
            "internal_only_ips": -5,
            # Escalating (positive) signals
            "threat_intel_match": 25,
            "related_open_incidents": 20,
            "high_value_asset": 15,
            "multi_tactic": 12,
            "rule_tp_rate_high": 10,
            "rare_external_ip": 8,
            "off_hours": 8,
            "many_alerts": 8,
        },
        # A rule needs at least this many closed incidents before its historical
        # FP rate is trusted as a signal.
        "min_closed_for_history": 5,
        # An entity seen on at least this many distinct days is "very common".
        "common_entity_min_days": 10,
        # Alerts above this count trigger the many_alerts signal.
        "many_alerts_min": 5,
    },
    "enrichment": {
        "enabled": True,
        "timeout_seconds": 90,
        "lookback": {
            "rule_history": "90d",
            "prior_closures": "30d",
            "related_incidents": "24h",
            "prevalence": "14d",
            "threat_intel": "30d",
        },
        "max_entities_per_query": 25,
        "ip_prevalence_sources": [
            {"table": "CommonSecurityLog", "column": "SourceIP"},
            {"table": "CommonSecurityLog", "column": "DestinationIP"},
            {"table": "SigninLogs", "column": "IPAddress"},
            {"table": "AzureActivity", "column": "CallerIpAddress"},
            {"table": "DeviceNetworkEvents", "column": "RemoteIP"},
        ],
        "account_prevalence_sources": [
            {"table": "SigninLogs", "column": "UserPrincipalName"},
            {"table": "SecurityEvent", "column": "TargetUserName"},
            {"table": "AuditLogs", "column": "InitiatedBy"},
        ],
    },
    "known_good": {
        "ip_ranges": [],
        "accounts": [],
        "hosts": [],
        "domains": [],
    },
    "service_accounts": {
        # Machine accounts end in $; svc-/svc_ is the common naming convention.
        "patterns": [r"^svc[-_.]", r"\$$", r"^gmsa[-_.]"],
    },
    "high_value_assets": {
        "hosts": [],
        "accounts": [],
    },
    "business_hours": {
        "enabled": True,
        "timezone": "UTC",
        "start_hour": 7,
        "end_hour": 19,
        # 0 = Monday ... 6 = Sunday
        "workdays": [0, 1, 2, 3, 4],
    },
    "suppressions": [],
    "actions": {
        "dry_run": False,
        "add_comment": True,
        "add_labels": True,
        "label_prefix": "triage",
        "suggest_severity": True,
        "auto_close": {
            "enabled": False,
            "min_confidence": 85,
            "max_score": 20,
            "classification": "BenignPositive",
            # Empty list means "no rule is eligible"; auto-close is opt-in per rule.
            "allowed_rules": [],
        },
    },
    "llm": {
        "provider": "none",  # none | azure_openai | anthropic
        "model": "",
        "endpoint": "",
        # Caps thinking plus response text on models with thinking enabled, so
        # leave headroom above the ~400 tokens the narrative itself needs.
        "max_tokens": 4096,
        # Anthropic only: low | medium | high | xhigh | max.
        "effort": "low",
        # Azure OpenAI only; current Claude models reject sampling parameters.
        "temperature": 0.0,
        "timeout_seconds": 45,
        # The LLM may raise the disposition but never lower it.
        "allow_escalation": True,
    },
    "polling": {
        "lookback": "4h",
        "max_incidents": 50,
        "statuses": ["New", "Active"],
        # Incidents already carrying a triage label are skipped.
        "skip_labeled": True,
    },
}


CONFIG_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "version": {"type": "integer", "minimum": 1},
        "scoring": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "baseline_by_severity": {
                    "type": "object",
                    "additionalProperties": {"type": "number"},
                },
                "thresholds": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "false_positive_max": {"type": "number", "minimum": 0, "maximum": 100},
                        "true_positive_min": {"type": "number", "minimum": 0, "maximum": 100},
                        "min_confidence_for_fp": {"type": "number", "minimum": 0, "maximum": 100},
                    },
                },
                "weights": {"type": "object", "additionalProperties": {"type": "number"}},
                "min_closed_for_history": {"type": "integer", "minimum": 1},
                "common_entity_min_days": {"type": "integer", "minimum": 1},
                "many_alerts_min": {"type": "integer", "minimum": 1},
            },
        },
        "enrichment": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "enabled": {"type": "boolean"},
                "timeout_seconds": {"type": "integer", "minimum": 5, "maximum": 600},
                "lookback": {"type": "object", "additionalProperties": {"type": "string"}},
                "max_entities_per_query": {"type": "integer", "minimum": 1, "maximum": 200},
                "ip_prevalence_sources": {"$ref": "#/$defs/sourceList"},
                "account_prevalence_sources": {"$ref": "#/$defs/sourceList"},
            },
        },
        "known_good": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "ip_ranges": {"type": "array", "items": {"type": "string"}},
                "accounts": {"type": "array", "items": {"type": "string"}},
                "hosts": {"type": "array", "items": {"type": "string"}},
                "domains": {"type": "array", "items": {"type": "string"}},
            },
        },
        "service_accounts": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"patterns": {"type": "array", "items": {"type": "string"}}},
        },
        "high_value_assets": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "hosts": {"type": "array", "items": {"type": "string"}},
                "accounts": {"type": "array", "items": {"type": "string"}},
            },
        },
        "business_hours": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "enabled": {"type": "boolean"},
                "timezone": {"type": "string"},
                "start_hour": {"type": "integer", "minimum": 0, "maximum": 23},
                "end_hour": {"type": "integer", "minimum": 1, "maximum": 24},
                "workdays": {
                    "type": "array",
                    "items": {"type": "integer", "minimum": 0, "maximum": 6},
                },
            },
        },
        "suppressions": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "reason"],
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "reason": {"type": "string", "minLength": 1},
                    "rule_names": {"type": "array", "items": {"type": "string"}},
                    "titles": {"type": "array", "items": {"type": "string"}},
                    "max_severity": {"type": "string"},
                    "entities": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "ip_ranges": {"type": "array", "items": {"type": "string"}},
                            "accounts": {"type": "array", "items": {"type": "string"}},
                            "hosts": {"type": "array", "items": {"type": "string"}},
                        },
                    },
                },
            },
        },
        "actions": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "dry_run": {"type": "boolean"},
                "add_comment": {"type": "boolean"},
                "add_labels": {"type": "boolean"},
                "label_prefix": {"type": "string", "minLength": 1},
                "suggest_severity": {"type": "boolean"},
                "auto_close": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "enabled": {"type": "boolean"},
                        "min_confidence": {"type": "number", "minimum": 0, "maximum": 100},
                        "max_score": {"type": "number", "minimum": 0, "maximum": 100},
                        "classification": {
                            "type": "string",
                            "enum": ["BenignPositive", "FalsePositive", "Undetermined"],
                        },
                        "allowed_rules": {"type": "array", "items": {"type": "string"}},
                    },
                },
            },
        },
        "llm": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "provider": {"type": "string", "enum": ["none", "azure_openai", "anthropic"]},
                "model": {"type": "string"},
                "endpoint": {"type": "string"},
                "max_tokens": {"type": "integer", "minimum": 64, "maximum": 32000},
                "effort": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "xhigh", "max"],
                },
                "temperature": {"type": "number", "minimum": 0, "maximum": 2},
                "timeout_seconds": {"type": "integer", "minimum": 5, "maximum": 300},
                "allow_escalation": {"type": "boolean"},
            },
        },
        "polling": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "lookback": {"type": "string"},
                "max_incidents": {"type": "integer", "minimum": 1, "maximum": 1000},
                "statuses": {"type": "array", "items": {"type": "string"}},
                "skip_labeled": {"type": "boolean"},
            },
        },
    },
    "$defs": {
        "sourceList": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["table", "column"],
                "properties": {
                    "table": {"type": "string", "pattern": r"^[A-Za-z_][A-Za-z0-9_]*$"},
                    "column": {"type": "string", "pattern": r"^[A-Za-z_][A-Za-z0-9_]*$"},
                },
            },
        }
    },
}


# --------------------------------------------------------------------------- #
# Workspace / connection settings
# --------------------------------------------------------------------------- #


@dataclass
class WorkspaceSettings:
    """Where the incidents live."""

    subscription_id: str
    resource_group: str
    workspace_name: str
    # The Log Analytics *workspace id* (GUID) used by the query API.
    workspace_id: str = ""
    arm_endpoint: str = "https://management.azure.com"
    # Audience for Log Analytics data-plane queries.
    logs_endpoint: str = "https://api.loganalytics.io"

    @property
    def workspace_arm_id(self) -> str:
        return (
            f"/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}"
        )

    @property
    def sentinel_base(self) -> str:
        return f"{self.workspace_arm_id}/providers/Microsoft.SecurityInsights"

    @classmethod
    def from_env(cls, env: Optional[Dict[str, str]] = None) -> "WorkspaceSettings":
        env = env if env is not None else dict(os.environ)
        missing = [
            key
            for key in ("AZURE_SUBSCRIPTION_ID", "SENTINEL_RESOURCE_GROUP", "SENTINEL_WORKSPACE_NAME")
            if not env.get(key)
        ]
        if missing:
            raise ConfigError(
                "Missing required environment variables: " + ", ".join(sorted(missing))
            )
        return cls(
            subscription_id=env["AZURE_SUBSCRIPTION_ID"].strip(),
            resource_group=env["SENTINEL_RESOURCE_GROUP"].strip(),
            workspace_name=env["SENTINEL_WORKSPACE_NAME"].strip(),
            workspace_id=(env.get("SENTINEL_WORKSPACE_ID") or "").strip(),
            arm_endpoint=(env.get("AZURE_ARM_ENDPOINT") or "https://management.azure.com").rstrip("/"),
            logs_endpoint=(env.get("AZURE_LOGS_ENDPOINT") or "https://api.loganalytics.io").rstrip("/"),
        )


# --------------------------------------------------------------------------- #
# Compiled config
# --------------------------------------------------------------------------- #


@dataclass
class Suppression:
    """A configured rule that forces an incident to likely-false-positive."""

    name: str
    reason: str
    rule_names: List[str] = field(default_factory=list)
    titles: List[str] = field(default_factory=list)
    max_severity: Optional[str] = None
    ip_ranges: List[str] = field(default_factory=list)
    accounts: List[str] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)


@dataclass
class TriageConfig:
    """Validated configuration with pre-compiled matchers."""

    raw: Dict[str, Any]
    known_good_networks: List[Any] = field(default_factory=list)
    known_good_accounts: List[re.Pattern] = field(default_factory=list)
    known_good_hosts: List[re.Pattern] = field(default_factory=list)
    known_good_domains: List[re.Pattern] = field(default_factory=list)
    service_account_patterns: List[re.Pattern] = field(default_factory=list)
    high_value_hosts: List[re.Pattern] = field(default_factory=list)
    high_value_accounts: List[re.Pattern] = field(default_factory=list)
    suppressions: List[Suppression] = field(default_factory=list)

    # Convenience accessors -------------------------------------------------- #
    @property
    def scoring(self) -> Dict[str, Any]:
        return self.raw["scoring"]

    @property
    def weights(self) -> Dict[str, float]:
        return self.raw["scoring"]["weights"]

    @property
    def thresholds(self) -> Dict[str, float]:
        return self.raw["scoring"]["thresholds"]

    @property
    def enrichment(self) -> Dict[str, Any]:
        return self.raw["enrichment"]

    @property
    def actions(self) -> Dict[str, Any]:
        return self.raw["actions"]

    @property
    def llm(self) -> Dict[str, Any]:
        return self.raw["llm"]

    @property
    def polling(self) -> Dict[str, Any]:
        return self.raw["polling"]

    @property
    def business_hours(self) -> Dict[str, Any]:
        return self.raw["business_hours"]

    def weight(self, name: str) -> float:
        """Weight for a signal, falling back to the built-in default."""
        if name in self.weights:
            return float(self.weights[name])
        return float(DEFAULT_CONFIG["scoring"]["weights"].get(name, 0))

    def lookback(self, name: str) -> str:
        configured = self.enrichment.get("lookback", {})
        if name in configured:
            return str(configured[name])
        return str(DEFAULT_CONFIG["enrichment"]["lookback"][name])


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge ``override`` into a copy of ``base``.

    Lists replace wholesale rather than concatenating, so a user can empty out a
    default source list instead of being stuck with it.
    """
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _compile_patterns(values: List[str], label: str) -> List[re.Pattern]:
    compiled = []
    for value in values:
        try:
            compiled.append(re.compile(value, re.IGNORECASE))
        except re.error as exc:
            raise ConfigError(f"Invalid regex in {label}: {value!r} ({exc})") from exc
    return compiled


def _compile_networks(values: List[str], label: str) -> List[Any]:
    networks = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ConfigError(f"Invalid IP range in {label}: {value!r} ({exc})") from exc
    return networks


_DURATION_RE = re.compile(r"^\d+(?:\.\d+)?(?:d|h|m|s)$")


def _validate_durations(data: Dict[str, Any]) -> None:
    """KQL timespan literals are interpolated into queries, so validate strictly."""
    for name, value in data.get("enrichment", {}).get("lookback", {}).items():
        if not _DURATION_RE.match(str(value)):
            raise ConfigError(
                f"enrichment.lookback.{name} must be a KQL timespan like '30d', got {value!r}"
            )
    lookback = data.get("polling", {}).get("lookback")
    if lookback is not None and not _DURATION_RE.match(str(lookback)):
        raise ConfigError(f"polling.lookback must be a KQL timespan like '4h', got {lookback!r}")


def compile_config(data: Dict[str, Any]) -> TriageConfig:
    """Validate a raw config dict and pre-compile its matchers."""
    merged = _deep_merge(DEFAULT_CONFIG, data or {})

    if jsonschema is not None:
        try:
            jsonschema.validate(instance=merged, schema=CONFIG_SCHEMA)
        except jsonschema.ValidationError as exc:  # pragma: no cover - message formatting
            location = "/".join(str(p) for p in exc.absolute_path) or "<root>"
            raise ConfigError(f"Invalid config at {location}: {exc.message}") from exc

    _validate_durations(merged)

    thresholds = merged["scoring"]["thresholds"]
    if thresholds["false_positive_max"] >= thresholds["true_positive_min"]:
        raise ConfigError(
            "scoring.thresholds.false_positive_max must be lower than true_positive_min"
        )

    business = merged["business_hours"]
    if business["start_hour"] >= business["end_hour"]:
        raise ConfigError("business_hours.start_hour must be earlier than end_hour")

    suppressions = []
    for entry in merged.get("suppressions", []):
        entities = entry.get("entities", {}) or {}
        suppression = Suppression(
            name=entry["name"],
            reason=entry["reason"],
            rule_names=list(entry.get("rule_names", [])),
            titles=list(entry.get("titles", [])),
            max_severity=entry.get("max_severity"),
            ip_ranges=list(entities.get("ip_ranges", [])),
            accounts=list(entities.get("accounts", [])),
            hosts=list(entities.get("hosts", [])),
        )
        # Fail fast on bad matchers rather than at triage time.
        _compile_networks(suppression.ip_ranges, f"suppressions[{suppression.name}].ip_ranges")
        _compile_patterns(suppression.accounts, f"suppressions[{suppression.name}].accounts")
        _compile_patterns(suppression.hosts, f"suppressions[{suppression.name}].hosts")
        _compile_patterns(suppression.rule_names, f"suppressions[{suppression.name}].rule_names")
        _compile_patterns(suppression.titles, f"suppressions[{suppression.name}].titles")
        suppressions.append(suppression)

    known_good = merged["known_good"]
    return TriageConfig(
        raw=merged,
        known_good_networks=_compile_networks(known_good["ip_ranges"], "known_good.ip_ranges"),
        known_good_accounts=_compile_patterns(known_good["accounts"], "known_good.accounts"),
        known_good_hosts=_compile_patterns(known_good["hosts"], "known_good.hosts"),
        known_good_domains=_compile_patterns(known_good["domains"], "known_good.domains"),
        service_account_patterns=_compile_patterns(
            merged["service_accounts"]["patterns"], "service_accounts.patterns"
        ),
        high_value_hosts=_compile_patterns(
            merged["high_value_assets"]["hosts"], "high_value_assets.hosts"
        ),
        high_value_accounts=_compile_patterns(
            merged["high_value_assets"]["accounts"], "high_value_assets.accounts"
        ),
        suppressions=suppressions,
    )


def _read_config_file(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        raise ConfigError(f"Config file not found: {path}")
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    if path.endswith((".yaml", ".yml")):
        if yaml is None:
            raise ConfigError(
                f"{path} is YAML but PyYAML is not installed; install pyyaml or use JSON"
            )
        loaded = yaml.safe_load(text)
    else:
        loaded = json.loads(text)
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ConfigError(f"Config root must be a mapping, got {type(loaded).__name__}")
    return loaded


def _env_bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


def _apply_env_overrides(data: Dict[str, Any], env: Dict[str, str]) -> Dict[str, Any]:
    """Let deployment-time env vars override file settings.

    Only the handful of knobs an operator flips per environment are exposed;
    everything else stays in the versioned config file.
    """
    overrides: Dict[str, Any] = {}

    def put(path: List[str], value: Any) -> None:
        cursor = overrides
        for key in path[:-1]:
            cursor = cursor.setdefault(key, {})
        cursor[path[-1]] = value

    if "TRIAGE_DRY_RUN" in env:
        put(["actions", "dry_run"], _env_bool(env["TRIAGE_DRY_RUN"]))
    if "TRIAGE_AUTO_CLOSE" in env:
        put(["actions", "auto_close", "enabled"], _env_bool(env["TRIAGE_AUTO_CLOSE"]))
    if env.get("TRIAGE_LLM_PROVIDER"):
        put(["llm", "provider"], env["TRIAGE_LLM_PROVIDER"].strip())
    if env.get("TRIAGE_LLM_MODEL"):
        put(["llm", "model"], env["TRIAGE_LLM_MODEL"].strip())
    if env.get("TRIAGE_LLM_ENDPOINT"):
        put(["llm", "endpoint"], env["TRIAGE_LLM_ENDPOINT"].strip())
    if env.get("TRIAGE_POLL_LOOKBACK"):
        put(["polling", "lookback"], env["TRIAGE_POLL_LOOKBACK"].strip())
    if "TRIAGE_ENRICHMENT_ENABLED" in env:
        put(["enrichment", "enabled"], _env_bool(env["TRIAGE_ENRICHMENT_ENABLED"]))

    if not overrides:
        return data
    return _deep_merge(data, overrides)


def load_config(
    path: Optional[str] = None, env: Optional[Dict[str, str]] = None
) -> TriageConfig:
    """Load config from ``path`` (or ``TRIAGE_CONFIG_PATH``), applying env overrides.

    With no file at all the built-in defaults are used, which is a valid
    configuration: rules-only triage, comment and label, no auto-close.
    """
    env = env if env is not None else dict(os.environ)
    path = path or env.get("TRIAGE_CONFIG_PATH") or ""

    data: Dict[str, Any] = {}
    if path:
        data = _read_config_file(path)
    else:
        # Look next to the deployed function app before falling back to defaults.
        for candidate in ("triage.yaml", "triage.yml", "triage.json", "config/triage.yaml"):
            here = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), candidate)
            if os.path.exists(here):
                data = _read_config_file(here)
                break

    data = _apply_env_overrides(data, env)
    return compile_config(data)
