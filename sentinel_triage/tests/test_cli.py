"""Tests for the CLI, including the offline replay path against the fixtures."""

from __future__ import annotations

import json
import os

import pytest

from triage.cli import build_parser, main

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
INCIDENT = os.path.join(FIXTURES, "incident-noisy-scanner.json")
ENRICHMENT = os.path.join(FIXTURES, "enrichment-noisy-scanner.json")
CONFIG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "triage.yaml"
)


def test_validate_accepts_the_shipped_config(capsys):
    assert main(["validate", "-c", CONFIG]) == 0
    assert "Config is valid" in capsys.readouterr().out


def test_validate_reports_a_bad_config(tmp_path, capsys):
    bad = tmp_path / "triage.json"
    bad.write_text(json.dumps({"scoring": {"thresholds": {"false_positive_max": 90}}}))

    assert main(["validate", "-c", str(bad)]) == 2
    assert "Configuration error" in capsys.readouterr().err


def test_missing_config_file_exits_cleanly(capsys):
    assert main(["validate", "-c", "/nope/triage.yaml"]) == 2
    assert "Configuration error" in capsys.readouterr().err


def test_replay_scores_the_scanner_fixture_as_a_false_positive(capsys):
    """The end-to-end offline path: fixture in, explained verdict out."""
    assert main(["replay", "-c", CONFIG, INCIDENT, "--enrichment", ENRICHMENT]) == 0

    out = capsys.readouterr().out
    assert "LikelyFalsePositive" in out
    assert "#10472" in out
    # The verdict must be traceable to named evidence, not just a number.
    assert "prior_fp_closure" in out
    assert "rule_fp_rate_high" in out
    assert "6 ok, 0 failed" in out or "confidence" in out


def test_replay_without_enrichment_stays_cautious(capsys):
    """No evidence gathered means no confident false-positive call."""
    assert main(["replay", "-c", CONFIG, INCIDENT]) == 0

    out = capsys.readouterr().out
    assert "NeedsReview" in out


def test_replay_renders_the_comment_on_request(capsys):
    assert main(
        ["replay", "-c", CONFIG, INCIDENT, "--enrichment", ENRICHMENT, "--show-comment"]
    ) == 0

    out = capsys.readouterr().out
    assert "## Automated triage" in out
    assert "| Impact | Signal | Evidence |" in out
    assert "Dry run" in out


def test_replay_reports_a_missing_incident_file(capsys):
    assert main(["replay", "/nope/incident.json"]) == 2
    assert "File not found" in capsys.readouterr().err


def test_shared_flags_are_accepted_before_and_after_the_subcommand():
    parser = build_parser()

    before = parser.parse_args(["-c", "a.yaml", "--show-comment", "validate"])
    after = parser.parse_args(["validate", "-c", "a.yaml", "--show-comment"])

    assert before.config == after.config == "a.yaml"
    assert before.show_comment is after.show_comment is True


def test_omitting_a_flag_after_the_subcommand_keeps_the_top_level_value():
    """SUPPRESS on the subparser must not clobber what the top level parsed."""
    parser = build_parser()
    args = parser.parse_args(["-c", "top.yaml", "validate"])

    assert args.config == "top.yaml"


def test_subcommand_is_required(capsys):
    with pytest.raises(SystemExit):
        build_parser().parse_args([])
