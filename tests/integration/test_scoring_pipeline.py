"""
tests/integration/test_scoring_pipeline.py — end-to-end scoring pipeline tests.

Simulates full task lifecycles (profile build → event stream → verdict) without
a running kernel or real Ollama instance. All external calls are mocked.
"""

import pytest
from unittest.mock import patch

from scorer import ScoringSession, TaskProfile, build_profile


# ── Scenario 1: write JSON file ───────────────────────────────────────────────


@pytest.mark.integration
def test_scenario_write_json_allowed_paths_then_unexpected_socket(mock_ollama_client):
    """Scenario 1: write JSON task — two allowed openat calls followed by an unexpected socket.

    Expected: openat to /tmp/ returns None twice; socket returns ALERT with score=40.
    """
    profile = build_profile("write JSON file")
    # mock_ollama_client returns: expected=["openat","write","close"], allowed=["/tmp/","/var/tmp/"]
    session = ScoringSession(profile=profile)

    r_open1 = session.score_event("openat", "/tmp/out.json")
    r_open2 = session.score_event("openat", "/tmp/out.json")
    r_socket = session.score_event("socket", "")

    assert r_open1 is None, "openat to /tmp/ should be benign"
    assert r_open2 is None, "second openat to /tmp/ should be benign"
    assert session.score == 40, f"score should be 40 after unexpected socket, got {session.score}"
    assert r_socket is not None
    assert r_socket.startswith("ALERT"), f"socket should raise ALERT, got: {r_socket}"
    assert "40" in r_socket


# ── Scenario 2: data processing + ptrace ─────────────────────────────────────


@pytest.mark.integration
def test_scenario_data_processing_ptrace_blocks_regardless_of_prior_score():
    """Scenario 2: data processing task — openat allowed, connect alerts, then ptrace blocks.

    Expected: openat to /proc/self/ is None; connect returns ALERT (score=60);
    ptrace returns BLOCK regardless of accumulated score.
    """
    profile = TaskProfile(
        task="data processing",
        expected_syscalls=["openat", "read", "close", "mmap", "brk"],
        allowed_paths=["/proc/self/", "/dev/urandom"],
    )
    session = ScoringSession(profile=profile)

    r_open = session.score_event("openat", "/proc/self/maps")
    r_connect = session.score_event("connect", "")
    r_ptrace = session.score_event("ptrace", "")

    assert r_open is None, "openat to /proc/self/ should be allowed"
    assert r_connect is not None and r_connect.startswith("ALERT"), (
        f"connect should be ALERT for data_processing profile, got: {r_connect}"
    )
    assert session.score >= 60, "score should be at least 60 after connect"
    assert r_ptrace is not None
    assert r_ptrace.startswith("BLOCK"), (
        f"ptrace must always return BLOCK regardless of prior score, got: {r_ptrace}"
    )
    assert "ptrace" in r_ptrace


# ── Scenario 3: threshold breach on second connect ────────────────────────────


@pytest.mark.integration
def test_scenario_threshold_breach_on_second_connect():
    """Scenario 3: two connect events breach the block threshold (60+60=120 ≥ 100).

    Expected: first connect → ALERT at score=60; second connect → BLOCK at score=120.
    """
    profile = TaskProfile(
        task="file write (no network)",
        expected_syscalls=["openat", "write", "close"],
        allowed_paths=["/tmp/"],
    )
    session = ScoringSession(profile=profile)

    r1 = session.score_event("connect", "")
    r2 = session.score_event("connect", "")

    assert r1 is not None, "first connect should raise an alert"
    assert r1.startswith("ALERT"), f"first connect should be ALERT, got: {r1}"
    assert session.score == 60 or "60" in r1, "score should be 60 after first connect"

    assert r2 is not None
    assert r2.startswith("BLOCK"), (
        f"second connect must trigger BLOCK when score ≥ 100, got: {r2}"
    )
    assert "THRESHOLD BREACHED" in r2
    assert "120" in r2


# ── Scenario 4: Ollama timeout — deny-all fallback ────────────────────────────


@pytest.mark.integration
def test_scenario_ollama_timeout_fallback_socket_alerts():
    """Scenario 4: when Ollama errors the fallback deny-all profile flags socket as ALERT.

    Expected: build_profile returns TaskProfile(expected_syscalls=["openat"], allowed_paths=[]);
    a socket event is unexpected and returns an ALERT string immediately.
    """
    with patch("ollama.Client") as MockClientClass:
        MockClientClass.return_value.chat.side_effect = TimeoutError("Ollama timeout")
        profile = build_profile("unknown data task")

    # fallback profile: expected_syscalls=["openat"], allowed_paths=[]
    assert profile.expected_syscalls == ["openat"]
    assert profile.allowed_paths == []

    session = ScoringSession(profile=profile)
    result = session.score_event("socket", "")

    assert result is not None, "socket should be flagged in deny-all profile"
    assert "ALERT" in result, (
        f"socket should produce ALERT under deny-all fallback, got: {result}"
    )
