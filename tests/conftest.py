"""
tests/conftest.py — shared fixtures for the llm-ebpf-guardian test suite.

Adds userspace/ to sys.path so tests can import scorer and loader directly
without needing an __init__.py in userspace/.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Make userspace modules importable as 'scorer' and 'loader'
_PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "userspace"))

from loader import GuardianEvent  # noqa: E402
from scorer import TaskProfile  # noqa: E402


@pytest.fixture
def mock_ollama_profile() -> TaskProfile:
    """Return a controlled TaskProfile for a 'write JSON file' task.

    expected_syscalls: openat, write, close
    allowed_paths:     /tmp/, /var/tmp/
    """
    return TaskProfile(
        task="write JSON file",
        expected_syscalls=["openat", "write", "close"],
        allowed_paths=["/tmp/", "/var/tmp/"],
        rationale="File write task only needs openat, write, and close.",
    )


@pytest.fixture
def mock_ollama_client(mock_ollama_profile: TaskProfile):
    """Patch ollama.Client so .chat() returns the JSON for mock_ollama_profile.

    Yields the mock Client *instance* so tests can inspect or override calls.
    """
    profile_json = json.dumps(
        {
            "expected_syscalls": mock_ollama_profile.expected_syscalls,
            "allowed_path_prefixes": mock_ollama_profile.allowed_paths,
            "rationale": mock_ollama_profile.rationale,
        }
    )
    with patch("ollama.Client") as MockClientClass:
        mock_instance = MagicMock()
        mock_instance.chat.return_value = {"message": {"content": profile_json}}
        MockClientClass.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def sample_event() -> GuardianEvent:
    """Return a pre-populated GuardianEvent for unit test convenience.

    pid=12345, syscall=4 (openat), comm=python3, path=/tmp/output.json
    """
    event = GuardianEvent()
    event.pid = 12345
    event.tgid = 12345
    event.uid = 1000
    event.syscall = 4  # SYS_OPENAT
    event.comm = b"python3"
    event.path = b"/tmp/output.json"
    return event
