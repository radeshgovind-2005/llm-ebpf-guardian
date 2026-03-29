"""
tests/unit/test_policy.py — unit tests for profiles/default_policy.yaml.

Validates schema correctness without executing any Python scoring logic.
"""

from pathlib import Path

import pytest
import yaml

_POLICY_PATH = Path(__file__).parent.parent.parent / "profiles" / "default_policy.yaml"

REQUIRED_PROFILE_KEYS = {"expected_syscalls", "allowed_path_prefixes", "default_action"}
REQUIRED_PROFILES = {"file_write", "file_read", "data_processing", "network_fetch", "unknown"}
REQUIRED_SYSCALLS_IN_WEIGHTS = {"execve", "socket", "connect", "openat", "ptrace", "mount"}


@pytest.fixture(scope="module")
def policy() -> dict:
    """Load the default_policy.yaml once for the entire test module."""
    with _POLICY_PATH.open() as fh:
        return yaml.safe_load(fh)


# ── Top-level structure ───────────────────────────────────────────────────────


def test_policy_file_exists():
    """Test that default_policy.yaml exists at the expected path."""
    assert _POLICY_PATH.exists(), f"Policy file not found: {_POLICY_PATH}"


def test_policy_has_profiles_key(policy):
    """Test that the YAML top level contains a 'profiles' mapping."""
    assert "profiles" in policy


def test_policy_has_score_weights_key(policy):
    """Test that the YAML top level contains a 'score_weights' mapping."""
    assert "score_weights" in policy


def test_policy_has_block_threshold(policy):
    """Test that the YAML top level contains a 'block_threshold' key."""
    assert "block_threshold" in policy


def test_block_threshold_is_integer(policy):
    """Test that block_threshold is an integer (not a string or float)."""
    assert isinstance(policy["block_threshold"], int)


def test_block_threshold_is_100(policy):
    """Test that block_threshold is 100, matching the value used in scorer.py."""
    assert policy["block_threshold"] == 100


# ── Profile presence ──────────────────────────────────────────────────────────


def test_all_five_profiles_exist(policy):
    """Test that all five expected task profiles are present in the YAML."""
    assert set(policy["profiles"].keys()) >= REQUIRED_PROFILES


@pytest.mark.parametrize("profile_name", sorted(REQUIRED_PROFILES))
def test_each_profile_has_required_keys(policy, profile_name):
    """Test that every profile has expected_syscalls, allowed_path_prefixes, and default_action."""
    profile = policy["profiles"][profile_name]
    missing = REQUIRED_PROFILE_KEYS - set(profile.keys())
    assert not missing, f"Profile '{profile_name}' is missing keys: {missing}"


@pytest.mark.parametrize("profile_name", sorted(REQUIRED_PROFILES))
def test_each_profile_expected_syscalls_is_list(policy, profile_name):
    """Test that expected_syscalls in every profile is a YAML sequence (list)."""
    syscalls = policy["profiles"][profile_name]["expected_syscalls"]
    assert isinstance(syscalls, list)
    assert len(syscalls) > 0, f"Profile '{profile_name}' has an empty expected_syscalls list"


@pytest.mark.parametrize("profile_name", sorted(REQUIRED_PROFILES))
def test_each_profile_allowed_path_prefixes_is_list(policy, profile_name):
    """Test that allowed_path_prefixes in every profile is a YAML sequence (list)."""
    prefixes = policy["profiles"][profile_name]["allowed_path_prefixes"]
    assert isinstance(prefixes, list)


@pytest.mark.parametrize("profile_name", sorted(REQUIRED_PROFILES))
def test_each_profile_default_action_is_valid(policy, profile_name):
    """Test that default_action in every profile is one of: alert, block, log."""
    action = policy["profiles"][profile_name]["default_action"]
    assert action in {"alert", "block", "log"}, (
        f"Profile '{profile_name}' has unexpected default_action: '{action}'"
    )


# ── score_weights ─────────────────────────────────────────────────────────────


def test_score_weights_contains_all_6_syscalls(policy):
    """Test that score_weights has entries for all 6 monitored syscalls."""
    assert set(policy["score_weights"].keys()) >= REQUIRED_SYSCALLS_IN_WEIGHTS


@pytest.mark.parametrize("syscall", sorted(REQUIRED_SYSCALLS_IN_WEIGHTS))
def test_score_weight_is_positive_integer(policy, syscall):
    """Test that each syscall weight is a positive integer."""
    weight = policy["score_weights"][syscall]
    assert isinstance(weight, int), f"Weight for '{syscall}' is not an int: {weight!r}"
    assert weight > 0, f"Weight for '{syscall}' must be positive, got {weight}"


def test_ptrace_weight_is_100(policy):
    """Test that ptrace weight is 100 (maximum — no legitimate use in sandboxed tasks)."""
    assert policy["score_weights"]["ptrace"] == 100


def test_mount_weight_is_100(policy):
    """Test that mount weight is 100 (maximum — always suspicious in sandboxed tasks)."""
    assert policy["score_weights"]["mount"] == 100


def test_connect_weight_is_60(policy):
    """Test that connect weight is 60, matching SCORE_WEIGHTS in scorer.py."""
    assert policy["score_weights"]["connect"] == 60


def test_openat_weight_is_10(policy):
    """Test that openat weight is 10, the lowest weight (path violations are minor)."""
    assert policy["score_weights"]["openat"] == 10
