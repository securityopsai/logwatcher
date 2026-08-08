"""Command line entry point.

Three modes, in increasing order of how much Azure they need:

``replay``  offline. Scores a saved incident JSON with no network at all.
``triage``  one live incident by number, GUID or ARM id.
``poll``    the same sweep the timer trigger runs.

Run ``replay`` first: it exercises the whole scoring path against a fixture and
tells you whether the config does what you think it does.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

from .actions import render_comment
from .agent import TriageAgent
from .config import ConfigError, TriageConfig, WorkspaceSettings, load_config
from .enrichment import Enricher
from .llm import build_provider
from .models import Enrichment, Incident, TriageResult
from .rules import RuleEngine
from .sentinel import SentinelClient, incident_name_from_arm_id, parse_incident


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    # These are chatty at DEBUG and drown out the triage output.
    for noisy in ("azure", "urllib3", "requests", "httpx"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _print_result(result: TriageResult, *, show_comment: bool) -> None:
    verdict = result.verdict
    print()
    print("=" * 78)
    print(result.summary())
    print("=" * 78)
    for reason in verdict.rationale:
        print(f"  · {reason}")
    if verdict.signals:
        print("\n  Signals:")
        for signal in verdict.top_signals(limit=20):
            # Format the sign into the number so the column stays aligned.
            points = f"{signal.points:+g}"
            print(f"    {points:>6}  {signal.name:<24} {signal.detail}")
    if result.enrichment.failures:
        print("\n  Enrichment gaps:")
        for name, error in sorted(result.enrichment.failures.items()):
            print(f"    ! {name}: {error}")
    if result.actions_taken:
        print("\n  Actions taken:")
        for action in result.actions_taken:
            print(f"    ✓ {action}")
    if result.actions_skipped:
        print("\n  Actions skipped:")
        for action in result.actions_skipped:
            print(f"    – {action}")
    if show_comment:
        print("\n  Comment body:")
        print("  " + "-" * 74)
        for line in render_comment(
            result.incident, result.enrichment, verdict, dry_run=result.dry_run
        ).splitlines():
            print(f"  {line}")
    print()


class _OfflineClient:
    """Stands in for :class:`SentinelClient` in replay mode.

    Every method either returns pre-canned data or raises, so a replay that
    accidentally reaches for the network fails loudly instead of hanging.
    """

    def __init__(self, rows_by_query: Optional[Dict[str, List[Dict[str, Any]]]] = None) -> None:
        self.rows = rows_by_query or {}
        self.writes: List[str] = []

    def query_logs(self, kql: str, timespan: Optional[str] = None) -> List[Dict[str, Any]]:
        for marker, rows in self.rows.items():
            if marker in kql:
                return rows
        return []

    def add_comment(self, incident_name: str, message: str, comment_id: str) -> None:
        self.writes.append(f"comment on {incident_name}")

    def update_incident(self, incident: Incident, **kwargs: Any) -> None:
        self.writes.append(f"update {incident.name}: {kwargs}")


def cmd_replay(args: argparse.Namespace) -> int:
    """Score a saved incident payload with no Azure access."""
    with open(args.incident, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    incident = parse_incident(payload)

    rows: Dict[str, List[Dict[str, Any]]] = {}
    if args.enrichment:
        with open(args.enrichment, "r", encoding="utf-8") as handle:
            rows = json.load(handle)

    config = load_config(args.config)
    # Replay never writes anywhere real, but make that explicit in the output.
    config.raw["actions"]["dry_run"] = True

    client = _OfflineClient(rows)
    enrichment = Enricher(client, config).enrich(incident) if rows else Enrichment()
    verdict = RuleEngine(config).evaluate(incident, enrichment)

    agent = TriageAgent(client, config, llm=build_provider(config) if args.llm else None)
    if not args.llm:
        verdict.narrative = agent._template_narrative(incident, verdict)
    else:
        verdict = agent._add_narrative(incident, enrichment, verdict)

    result = TriageResult(
        incident=incident, enrichment=enrichment, verdict=verdict, dry_run=True
    )
    _print_result(result, show_comment=args.show_comment)
    return 0


def _build_agent(args: argparse.Namespace) -> TriageAgent:
    env = dict(os.environ)
    if args.dry_run:
        env["TRIAGE_DRY_RUN"] = "true"
    config = load_config(args.config, env)
    settings = WorkspaceSettings.from_env(env)
    client = SentinelClient(
        settings, query_timeout=int(config.enrichment.get("timeout_seconds", 90))
    )
    return TriageAgent(client, config)


def cmd_triage(args: argparse.Namespace) -> int:
    agent = _build_agent(args)
    target = args.incident
    if target.startswith("/subscriptions/"):
        result = agent.triage_by_arm_id(target)
    elif target.isdigit():
        matches = agent.client.list_incidents(
            odata_filter=f"properties/incidentNumber eq {int(target)}", top=1
        )
        if not matches:
            print(f"No incident found with number {target}", file=sys.stderr)
            return 1
        result = agent.triage_incident(matches[0])
    else:
        result = agent.triage_by_name(target)
    _print_result(result, show_comment=args.show_comment)
    return 0


def cmd_poll(args: argparse.Namespace) -> int:
    agent = _build_agent(args)
    results = agent.poll(lookback=args.lookback, max_incidents=args.max_incidents)
    if not results:
        print("No untriaged incidents in the window.")
        return 0
    for result in results:
        _print_result(result, show_comment=args.show_comment)
    print(f"Triaged {len(results)} incident(s).")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Check the config file without touching Azure."""
    config = load_config(args.config)
    print(f"Config is valid ({args.config or 'built-in defaults'}).")
    print(f"  enrichment enabled : {config.enrichment.get('enabled')}")
    print(f"  dry run            : {config.actions.get('dry_run')}")
    print(f"  auto close         : {config.actions.get('auto_close', {}).get('enabled')}")
    print(f"  llm provider       : {config.llm.get('provider')}")
    print(f"  suppressions       : {len(config.suppressions)}")
    print(
        "  thresholds         : fp<={fp}, tp>={tp}, min-confidence-for-fp={mc}".format(
            fp=config.thresholds["false_positive_max"],
            tp=config.thresholds["true_positive_min"],
            mc=config.thresholds["min_confidence_for_fp"],
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="triage",
        description="Microsoft Sentinel incident triage agent",
    )
    parser.add_argument("-c", "--config", help="Path to triage.yaml (or .json)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    parser.add_argument(
        "--show-comment", action="store_true", help="Print the rendered Markdown comment"
    )

    # The same flags are accepted after the subcommand, which is where people
    # reach for them. SUPPRESS keeps an omitted flag from clobbering the value
    # already parsed off the top level.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-c", "--config", default=argparse.SUPPRESS, help="Path to triage.yaml (or .json)"
    )
    common.add_argument(
        "-v", "--verbose", action="store_true", default=argparse.SUPPRESS,
        help="Debug logging",
    )
    common.add_argument(
        "--show-comment", action="store_true", default=argparse.SUPPRESS,
        help="Print the rendered Markdown comment",
    )

    sub = parser.add_subparsers(dest="command", required=True, parser_class=argparse.ArgumentParser)

    replay = sub.add_parser(
        "replay", parents=[common], help="Score a saved incident JSON offline"
    )
    replay.add_argument("incident", help="Path to an incident payload (ARM or playbook shape)")
    replay.add_argument(
        "--enrichment",
        help="Optional JSON mapping a query substring to canned rows",
    )
    replay.add_argument(
        "--llm", action="store_true", help="Also call the configured LLM provider"
    )
    replay.set_defaults(func=cmd_replay)

    triage = sub.add_parser("triage", parents=[common], help="Triage one live incident")
    triage.add_argument("incident", help="Incident number, GUID name, or ARM resource id")
    triage.add_argument("--dry-run", action="store_true", help="Do not write to the incident")
    triage.set_defaults(func=cmd_triage)

    poll = sub.add_parser("poll", parents=[common], help="Triage recent untriaged incidents")
    poll.add_argument("--lookback", help="Window to scan, e.g. 4h or 2d")
    poll.add_argument("--max-incidents", type=int, help="Cap on incidents per run")
    poll.add_argument("--dry-run", action="store_true", help="Do not write to incidents")
    poll.set_defaults(func=cmd_poll)

    validate = sub.add_parser("validate", parents=[common], help="Validate the config file")
    validate.set_defaults(func=cmd_validate)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"File not found: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
