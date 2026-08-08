"""Shared fixtures. The rule engine is tested without touching Azure."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pytest

# The package lives inside the deployable function app directory.
APP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app")
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from triage.config import compile_config  # noqa: E402
from triage.models import (  # noqa: E402
    Alert,
    Entity,
    EntityKind,
    Incident,
)


@pytest.fixture
def config():
    """Built-in defaults, which are a valid production configuration."""
    return compile_config({})


def make_config(**overrides: Any):
    """Compile a config from the defaults plus a nested override dict."""
    return compile_config(overrides)


def make_incident(
    *,
    number: int = 4242,
    title: str = "Suspicious sign-in from unfamiliar location",
    severity: str = "Medium",
    status: str = "New",
    rule_names: Optional[List[str]] = None,
    entities: Optional[List[Entity]] = None,
    alerts: Optional[List[Alert]] = None,
    labels: Optional[List[str]] = None,
    activity_time: Optional[datetime] = None,
    alert_count: Optional[int] = None,
) -> Incident:
    """Build an incident with sensible defaults for the field under test."""
    if activity_time is None:
        # A Wednesday at 10:00 UTC — inside default business hours, so the
        # off-hours signal stays out of tests that are not about it.
        activity_time = datetime(2026, 3, 11, 10, 0, tzinfo=timezone.utc)

    rule_names = rule_names if rule_names is not None else ["Suspicious sign-in"]
    alerts = alerts if alerts is not None else [
        Alert(id="a1", name=rule_names[0] if rule_names else "alert", tactics=["InitialAccess"])
    ]

    return Incident(
        arm_id=(
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg"
            "/providers/Microsoft.OperationalInsights/workspaces/ws"
            f"/providers/Microsoft.SecurityInsights/incidents/inc-{number}"
        ),
        name=f"11111111-2222-3333-4444-{number:012d}",
        number=number,
        title=title,
        severity=severity,
        status=status,
        labels=labels or [],
        created_time=activity_time,
        first_activity_time=activity_time,
        alert_rule_names=rule_names,
        alert_count=alert_count if alert_count is not None else len(alerts),
        alerts=alerts,
        entities=entities or [],
        etag='"0x8DA"',
    )


def ip(value: str) -> Entity:
    return Entity(kind=EntityKind.IP, value=value)


def account(value: str) -> Entity:
    return Entity(kind=EntityKind.ACCOUNT, value=value)


def host(value: str) -> Entity:
    return Entity(kind=EntityKind.HOST, value=value)


class FakeSentinelClient:
    """Records writes and returns canned KQL rows keyed by query substring."""

    def __init__(self, rows_by_marker: Optional[Dict[str, List[Dict[str, Any]]]] = None) -> None:
        self.rows_by_marker = rows_by_marker or {}
        self.queries: List[str] = []
        self.comments: List[Dict[str, str]] = []
        self.updates: List[Dict[str, Any]] = []
        self.fail_markers: List[str] = []

    def query_logs(self, kql: str, timespan: Optional[str] = None) -> List[Dict[str, Any]]:
        self.queries.append(kql)
        for marker in self.fail_markers:
            if marker in kql:
                raise RuntimeError(f"simulated query failure for {marker}")
        for marker, rows in self.rows_by_marker.items():
            if marker in kql:
                return rows
        return []

    def add_comment(self, incident_name: str, message: str, comment_id: str) -> None:
        self.comments.append(
            {"incident": incident_name, "message": message, "id": comment_id}
        )

    def update_incident(self, incident: Incident, **kwargs: Any) -> None:
        self.updates.append({"incident": incident.name, **kwargs})

    def hydrate(self, incident: Incident) -> Incident:
        return incident


@pytest.fixture
def fake_client():
    return FakeSentinelClient()


def utc_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
