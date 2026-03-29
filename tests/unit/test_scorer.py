"""
tests/unit/test_scorer.py — unit tests for userspace/scorer.py.

All tests mock ollama.Client; no real Ollama or network calls are made.
"""

import pytest
from unittest.mock import MagicMock, patch

from scorer import (
    BLOCK_THRESHOLD,
    SCORE_WEIGHTS,
    ScoringSession,
    TaskProfile,
    build_profile,
)


# ── build_profile ─────────────────────────────────────────────────────────────


def test_build_profile_returns_correct_task_field(mock_ollama_client):
    """Test that build_profile stores the original task string in the returned profile."""
    profile = build_profile("write JSON file")
    assert profile.task == "write JSON file"


def test_build_profile_returns_correct_expected_syscalls(mock_ollama_client):
    """Test that build_profile parses expected_syscalls from the Ollama JSON response."""
    profile = build_profile("write JSON file")
    assert profile.expected_syscalls == ["openat", "write", "close"]


def test_build_profile_returns_correct_allowed_paths(mock_ollama_client):
    """Test that build_profile parses allowed_path_prefixes into profile.allowed_paths."""
    profile = build_profile("write JSON file")
    assert profile.allowed_paths == ["/tmp/", "/var/tmp/"]


def test_build_profile_returns_correct_rationale(mock_ollama_client):
    """Test that build_profile captures the rationale field from the Ollama response."""
    profile = build_profile("write JSON file")
    assert "write" in profile.rationale.lower() or len(profile.rationale) > 0


def test_build_profile_fallback_on_ollama_exception():
    """Test that build_profile returns a deny-all profile when Ollama raises an exception."""
    with patch("ollama.Client") as MockClientClass:
        MockClientClass.return_value.chat.side_effect = ConnectionError(
            "Ollama unreachable"
        )
        profile = build_profile("some task")

    assert profile.expected_syscalls == ["openat"]
    assert profile.allowed_paths == []


def test_build_profile_fallback_preserves_task_name():
    """Test that the fallback profile still stores the original task name."""
    with patch("ollama.Client") as MockClientClass:
        MockClientClass.return_value.chat.side_effect = RuntimeError("timeout")
        profile = build_profile("process data")

    assert profile.task == "process data"


# ── ScoringSession.score_event — always-block syscalls ───────────────────────


def test_score_event_ptrace_always_returns_block():
    """Test that ptrace is blocked regardless of what the task profile allows."""
    profile = TaskProfile(
        task="trusted task",
        expected_syscalls=["ptrace"],  # even if profile permits it
        allowed_paths=[],
    )
    session = ScoringSession(profile=profile)
    result = session.score_event("ptrace")
    assert result is not None
    assert result.startswith("BLOCK")


def test_score_event_mount_always_returns_block():
    """Test that mount is blocked regardless of what the task profile allows."""
    profile = TaskProfile(
        task="trusted task",
        expected_syscalls=["mount"],  # even if profile permits it
        allowed_paths=[],
    )
    session = ScoringSession(profile=profile)
    result = session.score_event("mount")
    assert result is not None
    assert result.startswith("BLOCK")


def test_score_event_ptrace_block_includes_syscall_name():
    """Test that the BLOCK string for ptrace contains 'ptrace'."""
    profile = TaskProfile(task="t", expected_syscalls=[], allowed_paths=[])
    session = ScoringSession(profile=profile)
    result = session.score_event("ptrace")
    assert "ptrace" in result


def test_score_event_mount_block_includes_syscall_name():
    """Test that the BLOCK string for mount contains 'mount'."""
    profile = TaskProfile(task="t", expected_syscalls=[], allowed_paths=[])
    session = ScoringSession(profile=profile)
    result = session.score_event("mount")
    assert "mount" in result


# ── ScoringSession.score_event — openat path checks ──────────────────────────


def test_score_event_openat_allowed_path_returns_none():
    """Test that openat with a path inside allowed_paths returns None (benign)."""
    profile = TaskProfile(
        task="file write",
        expected_syscalls=["openat"],
        allowed_paths=["/tmp/", "/var/tmp/"],
    )
    session = ScoringSession(profile=profile)
    result = session.score_event("openat", "/tmp/output.json")
    assert result is None


def test_score_event_openat_sub_path_allowed():
    """Test that openat with a deep sub-path under an allowed prefix returns None."""
    profile = TaskProfile(
        task="proc read",
        expected_syscalls=["openat"],
        allowed_paths=["/proc/self/"],
    )
    session = ScoringSession(profile=profile)
    result = session.score_event("openat", "/proc/self/maps")
    assert result is None


def test_score_event_openat_outside_allowed_path_returns_alert():
    """Test that openat with a path NOT in allowed_paths returns an ALERT string."""
    profile = TaskProfile(
        task="file write",
        expected_syscalls=["openat"],
        allowed_paths=["/tmp/", "/var/tmp/"],
    )
    session = ScoringSession(profile=profile)
    result = session.score_event("openat", "/etc/passwd")
    assert result is not None
    assert result.startswith("ALERT")
    assert "/etc/passwd" in result


def test_score_event_openat_outside_allowed_path_increases_score():
    """Test that an openat violation increases the session score by the openat weight."""
    profile = TaskProfile(task="t", expected_syscalls=["openat"], allowed_paths=[])
    session = ScoringSession(profile=profile)
    session.score_event("openat", "/etc/shadow")
    assert session.score == SCORE_WEIGHTS["openat"]


# ── ScoringSession.score_event — expected / unexpected syscalls ───────────────


def test_score_event_expected_syscall_returns_none():
    """Test that a syscall listed in expected_syscalls returns None (benign)."""
    profile = TaskProfile(
        task="network fetch",
        expected_syscalls=["socket", "connect"],
        allowed_paths=[],
    )
    session = ScoringSession(profile=profile)
    assert session.score_event("socket") is None
    assert session.score_event("connect") is None


def test_score_event_unexpected_syscall_returns_alert():
    """Test that an unexpected syscall (score < threshold) returns an ALERT string."""
    profile = TaskProfile(
        task="file write",
        expected_syscalls=["openat", "write", "close"],
        allowed_paths=["/tmp/"],
    )
    session = ScoringSession(profile=profile)
    result = session.score_event("socket")
    assert result is not None
    assert result.startswith("ALERT")
    assert "socket" in result


def test_score_event_unexpected_syscall_accumulates_score():
    """Test that each unexpected syscall adds its weight to the session score."""
    profile = TaskProfile(task="t", expected_syscalls=[], allowed_paths=[])
    session = ScoringSession(profile=profile)
    session.score_event("socket")   # +40
    assert session.score == SCORE_WEIGHTS["socket"]
    session.score_event("socket")   # +40 again
    assert session.score == SCORE_WEIGHTS["socket"] * 2


def test_score_event_unexpected_syscall_at_threshold_returns_block():
    """Test that an unexpected syscall pushing score >= BLOCK_THRESHOLD returns BLOCK."""
    profile = TaskProfile(task="t", expected_syscalls=[], allowed_paths=[])
    session = ScoringSession(profile=profile)
    # connect=60 → 60; second connect → 120 ≥ 100
    session.score_event("connect")
    result = session.score_event("connect")
    assert result is not None
    assert result.startswith("BLOCK")


def test_score_event_block_string_contains_threshold_breached():
    """Test that the BLOCK string for a threshold breach includes 'THRESHOLD BREACHED'."""
    profile = TaskProfile(task="t", expected_syscalls=[], allowed_paths=[])
    session = ScoringSession(profile=profile)
    session.score_event("connect")   # score=60
    result = session.score_event("connect")  # score=120
    assert "THRESHOLD BREACHED" in result


# ── Score accumulation ────────────────────────────────────────────────────────


def test_score_accumulates_across_multiple_events():
    """Test that score increases cumulatively across a sequence of events in one session."""
    profile = TaskProfile(task="t", expected_syscalls=[], allowed_paths=[])
    session = ScoringSession(profile=profile)

    assert session.score == 0
    session.score_event("socket")    # +40 → 40
    assert session.score == 40
    session.score_event("execve")    # +40 → 80
    assert session.score == 80


def test_score_not_increased_by_allowed_events():
    """Test that benign (allowed) events do not increase the session score."""
    profile = TaskProfile(
        task="file write",
        expected_syscalls=["openat", "write"],
        allowed_paths=["/tmp/"],
    )
    session = ScoringSession(profile=profile)

    session.score_event("openat", "/tmp/out.json")  # allowed path
    session.score_event("write")                     # expected syscall
    assert session.score == 0


# ── SCORE_WEIGHTS sanity ──────────────────────────────────────────────────────


def test_score_weights_connect_is_60():
    """Test that the connect weight is 60 as documented."""
    assert SCORE_WEIGHTS["connect"] == 60


def test_score_weights_socket_is_40():
    """Test that the socket weight is 40 as documented."""
    assert SCORE_WEIGHTS["socket"] == 40


def test_score_weights_ptrace_is_100():
    """Test that the ptrace weight is 100 (maximum, always block)."""
    assert SCORE_WEIGHTS["ptrace"] == 100


def test_score_weights_mount_is_100():
    """Test that the mount weight is 100 (maximum, always block)."""
    assert SCORE_WEIGHTS["mount"] == 100


def test_score_weights_openat_is_10():
    """Test that the openat weight is 10 (low, path violations are minor)."""
    assert SCORE_WEIGHTS["openat"] == 10


def test_score_weights_execve_is_40():
    """Test that the execve weight is 40 as documented."""
    assert SCORE_WEIGHTS["execve"] == 40


def test_score_weights_used_for_socket_scoring():
    """Test that scoring a socket event adds exactly SCORE_WEIGHTS['socket'] to score."""
    profile = TaskProfile(task="t", expected_syscalls=[], allowed_paths=[])
    session = ScoringSession(profile=profile)
    session.score_event("socket")
    assert session.score == SCORE_WEIGHTS["socket"]


def test_score_weights_used_for_connect_scoring():
    """Test that scoring a connect event adds exactly SCORE_WEIGHTS['connect'] to score."""
    profile = TaskProfile(task="t", expected_syscalls=[], allowed_paths=[])
    session = ScoringSession(profile=profile)
    session.score_event("connect")
    assert session.score == SCORE_WEIGHTS["connect"]


def test_score_weights_used_for_ptrace_scoring():
    """Test that scoring a ptrace event adds exactly SCORE_WEIGHTS['ptrace'] to score."""
    profile = TaskProfile(task="t", expected_syscalls=[], allowed_paths=[])
    session = ScoringSession(profile=profile)
    session.score_event("ptrace")
    assert session.score == SCORE_WEIGHTS["ptrace"]


def test_block_threshold_constant_is_100():
    """Test that BLOCK_THRESHOLD is 100 as documented."""
    assert BLOCK_THRESHOLD == 100
