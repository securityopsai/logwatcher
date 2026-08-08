"""Azure Functions entry point (Python v2 programming model).

Two triggers, both optional:

``triage_timer``  polls Sentinel on a schedule. This is the zero-extra-infra
                  path — it needs only the Function App and one role assignment,
                  and it works the moment the deployment finishes.
``triage_http``   near-real-time. A Sentinel automation rule fires the playbook,
                  which POSTs the incident's ARM id here.

The agent is built once per worker process because ``TriageAgent`` holds a
credential and a token cache; rebuilding it per invocation would re-authenticate
on every incident.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any, Dict, Optional

import azure.functions as func

from triage.agent import TriageAgent
from triage.config import ConfigError
from triage.models import TriageResult
from triage.sentinel import incident_name_from_arm_id

app = func.FunctionApp()
logger = logging.getLogger("sentinel_triage")

_agent: Optional[TriageAgent] = None
_agent_lock = threading.Lock()


def get_agent() -> TriageAgent:
    """Build the agent once per process."""
    global _agent
    if _agent is None:
        with _agent_lock:
            if _agent is None:
                _agent = TriageAgent.from_environment()
                logger.info(
                    "Triage agent ready (llm=%s, dry_run=%s, auto_close=%s)",
                    getattr(_agent.llm, "name", "none"),
                    _agent.config.actions.get("dry_run"),
                    _agent.config.actions.get("auto_close", {}).get("enabled"),
                )
    return _agent


def _summarize(result: TriageResult) -> Dict[str, Any]:
    return {
        "incidentNumber": result.incident.number,
        "incidentName": result.incident.name,
        "title": result.incident.title,
        "disposition": result.verdict.disposition.value,
        "score": result.verdict.score,
        "confidence": result.verdict.confidence,
        "signals": [
            {"name": s.name, "points": s.points, "detail": s.detail}
            for s in result.verdict.top_signals()
        ],
        "actionsTaken": result.actions_taken,
        "actionsSkipped": result.actions_skipped,
        "enrichmentFailures": result.enrichment.failures,
        "dryRun": result.dry_run,
        "error": result.error,
    }


@app.function_name(name="triage_http")
@app.route(route="triage", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def triage_http(req: func.HttpRequest) -> func.HttpResponse:
    """Triage a single incident named in the request body.

    Accepts ``{"incidentArmId": "..."}``, ``{"incidentName": "<guid>"}``, or a
    raw Sentinel playbook trigger body. In every case the incident is re-fetched
    from ARM so triage runs against canonical data rather than whatever shape the
    caller happened to send.
    """
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Request body must be JSON"}),
            status_code=400,
            mimetype="application/json",
        )

    incident_name = _extract_incident_name(body)
    if not incident_name:
        return func.HttpResponse(
            json.dumps(
                {
                    "error": (
                        "Could not determine the incident. Send incidentArmId, "
                        "incidentName, or the Sentinel incident trigger body."
                    )
                }
            ),
            status_code=400,
            mimetype="application/json",
        )

    try:
        agent = get_agent()
    except ConfigError as exc:
        logger.error("Configuration error: %s", exc)
        return func.HttpResponse(
            json.dumps({"error": f"Configuration error: {exc}"}),
            status_code=500,
            mimetype="application/json",
        )

    try:
        result = agent.triage_by_name(incident_name)
    except Exception as exc:  # noqa: BLE001 - surface the failure to the playbook
        logger.exception("Triage failed for %s", incident_name)
        return func.HttpResponse(
            json.dumps({"error": str(exc), "incidentName": incident_name}),
            status_code=500,
            mimetype="application/json",
        )

    return func.HttpResponse(
        json.dumps(_summarize(result)), status_code=200, mimetype="application/json"
    )


def _extract_incident_name(body: Any) -> Optional[str]:
    """Pull an incident GUID out of any of the accepted request shapes."""
    if not isinstance(body, dict):
        return None

    if body.get("incidentName"):
        return str(body["incidentName"])

    arm_id = body.get("incidentArmId") or body.get("incidentId")
    if not arm_id:
        # Sentinel's incident trigger nests the resource under "object".
        obj = body.get("object")
        if isinstance(obj, dict):
            arm_id = obj.get("id")
            if not arm_id and obj.get("name"):
                return str(obj["name"])
    if not arm_id:
        arm_id = body.get("id")

    if arm_id:
        try:
            return incident_name_from_arm_id(str(arm_id))
        except ValueError:
            logger.warning("Request carried an id that is not an incident: %r", arm_id)
    return None


@app.function_name(name="triage_timer")
@app.timer_trigger(
    schedule="%TRIAGE_POLL_SCHEDULE%",
    arg_name="timer",
    run_on_startup=False,
    use_monitor=True,
)
def triage_timer(timer: func.TimerRequest) -> None:
    """Sweep recent untriaged incidents on a schedule."""
    if timer.past_due:
        logger.warning("Timer is past due; the previous run may have overrun")

    if os.environ.get("TRIAGE_POLL_ENABLED", "true").strip().lower() not in (
        "1",
        "true",
        "yes",
        "on",
    ):
        logger.info("Polling disabled via TRIAGE_POLL_ENABLED")
        return

    try:
        agent = get_agent()
    except ConfigError as exc:
        logger.error("Configuration error, skipping poll: %s", exc)
        return

    results = agent.poll()
    if not results:
        logger.info("Poll complete: nothing to triage")
        return

    counts: Dict[str, int] = {}
    for result in results:
        key = result.verdict.disposition.value
        counts[key] = counts.get(key, 0) + 1
    logger.info("Poll complete: triaged %d incident(s) — %s", len(results), counts)


@app.function_name(name="health")
@app.route(route="health", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def health(req: func.HttpRequest) -> func.HttpResponse:
    """Liveness plus a configuration echo, so a deploy can be verified.

    Deliberately reports configuration only — no workspace names, no incident
    data — since this route is anonymous.
    """
    payload: Dict[str, Any] = {"status": "ok"}
    try:
        agent = get_agent()
        payload.update(
            {
                "llmProvider": getattr(agent.llm, "name", "none"),
                "dryRun": bool(agent.config.actions.get("dry_run")),
                "autoCloseEnabled": bool(
                    agent.config.actions.get("auto_close", {}).get("enabled")
                ),
                "enrichmentEnabled": bool(agent.config.enrichment.get("enabled")),
                "suppressionRules": len(agent.config.suppressions),
            }
        )
    except Exception as exc:  # noqa: BLE001
        payload = {"status": "degraded", "error": str(exc)}
        return func.HttpResponse(
            json.dumps(payload), status_code=503, mimetype="application/json"
        )
    return func.HttpResponse(json.dumps(payload), status_code=200, mimetype="application/json")
