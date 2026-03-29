"""
tests/unit/test_loader.py — unit tests for userspace/loader.py.

Tests run without a real BPF kernel or CAP_BPF — all console output is mocked.
"""

import ctypes

import pytest
from unittest.mock import patch

from loader import (
    GuardianEvent,
    PATH_LEN,
    SYSCALL_NAMES,
    TASK_COMM_LEN,
    print_event,
)

# Expected total size of GuardianEvent, derived from guardian.h field layout:
#   u64 timestamp_ns      offset   0, size 8
#   u32 pid               offset   8, size 4
#   u32 tgid              offset  12, size 4
#   u32 uid               offset  16, size 4
#   u32 syscall (enum)    offset  20, size 4
#   char comm[16]         offset  24, size 16
#   char path[128]        offset  40, size 128
#   u16 socket_family     offset 168, size 2
#   --- 2 bytes padding ---
#   u32 remote_addr       offset 172, size 4
#   u16 remote_port       offset 176, size 2
#   --- 2 bytes padding ---
#   u32 ret               offset 180, size 4
#   Total: 184 bytes (aligned to 8-byte struct boundary)
EXPECTED_STRUCT_SIZE = 184


# ── Struct size and layout ────────────────────────────────────────────────────


def test_guardian_event_struct_size_matches_c_layout():
    """Test that GuardianEvent ctypes struct size matches the C compiler layout (184 bytes)."""
    assert ctypes.sizeof(GuardianEvent) == EXPECTED_STRUCT_SIZE


def test_task_comm_len_is_16():
    """Test that TASK_COMM_LEN equals 16, matching the #define in guardian.h."""
    assert TASK_COMM_LEN == 16


def test_path_len_is_128():
    """Test that PATH_LEN equals 128, matching the #define in guardian.h."""
    assert PATH_LEN == 128


def test_guardian_event_comm_field_is_16_bytes():
    """Test that the comm field in GuardianEvent is exactly TASK_COMM_LEN bytes wide."""
    # Use the CField class descriptor's .size — instance access returns bytes, not a ctypes type
    assert GuardianEvent.comm.size == TASK_COMM_LEN


def test_guardian_event_path_field_is_128_bytes():
    """Test that the path field in GuardianEvent is exactly PATH_LEN bytes wide."""
    assert GuardianEvent.path.size == PATH_LEN


# ── SYSCALL_NAMES coverage ────────────────────────────────────────────────────


def test_syscall_names_covers_all_6_ids():
    """Test that SYSCALL_NAMES maps all 6 monitored syscall IDs (1–6)."""
    assert set(SYSCALL_NAMES.keys()) == {1, 2, 3, 4, 5, 6}


def test_syscall_names_correct_mapping():
    """Test that each syscall ID maps to the correct name as defined in guardian.h."""
    assert SYSCALL_NAMES[1] == "execve"
    assert SYSCALL_NAMES[2] == "socket"
    assert SYSCALL_NAMES[3] == "connect"
    assert SYSCALL_NAMES[4] == "openat"
    assert SYSCALL_NAMES[5] == "ptrace"
    assert SYSCALL_NAMES[6] == "mount"


# ── print_event — no crash ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "syscall_id,comm,path",
    [
        (1, b"python3", b"/usr/bin/python3"),    # execve
        (2, b"python3", b""),                    # socket
        (3, b"python3", b""),                    # connect
        (4, b"python3", b"/tmp/output.json"),    # openat
        (5, b"python3", b""),                    # ptrace
        (6, b"python3", b""),                    # mount
    ],
    ids=["execve", "socket", "connect", "openat", "ptrace", "mount"],
)
def test_print_event_doesnt_crash_for_each_syscall(syscall_id, comm, path):
    """Test that print_event completes without raising for every monitored syscall type."""
    event = GuardianEvent()
    event.pid = 1
    event.syscall = syscall_id
    event.comm = comm
    event.path = path

    with patch("loader.console") as mock_console:
        print_event(event)  # must not raise

    mock_console.print.assert_called_once()


# ── print_event — colour coding ───────────────────────────────────────────────


@pytest.mark.parametrize(
    "syscall_id,expected_colour",
    [
        (5, "red"),     # ptrace
        (6, "red"),     # mount
        (2, "yellow"),  # socket
        (3, "yellow"),  # connect
        (1, "cyan"),    # execve
        (4, "white"),   # openat
    ],
    ids=["ptrace", "mount", "socket", "connect", "execve", "openat"],
)
def test_print_event_colour_coding(syscall_id, expected_colour):
    """Test that print_event uses the correct Rich colour tag for each syscall risk level."""
    event = GuardianEvent()
    event.pid = 1
    event.syscall = syscall_id
    event.comm = b"test"
    event.path = b""

    with patch("loader.console") as mock_console:
        print_event(event)

    output_string = mock_console.print.call_args[0][0]
    assert f"[{expected_colour}]" in output_string
    assert f"[/{expected_colour}]" in output_string


# ── GuardianEvent field read/write ────────────────────────────────────────────


def test_guardian_event_pid_field_roundtrip():
    """Test that GuardianEvent.pid can be set to an arbitrary value and read back correctly."""
    event = GuardianEvent()
    event.pid = 99999
    assert event.pid == 99999


def test_guardian_event_syscall_field_roundtrip():
    """Test that GuardianEvent.syscall can be set and read back for each valid syscall ID."""
    event = GuardianEvent()
    for sid in range(1, 7):
        event.syscall = sid
        assert event.syscall == sid


def test_guardian_event_comm_field_roundtrip():
    """Test that GuardianEvent.comm stores and returns a byte string correctly."""
    event = GuardianEvent()
    event.comm = b"python3"
    assert event.comm == b"python3"


def test_guardian_event_path_field_roundtrip():
    """Test that GuardianEvent.path stores and returns a byte string correctly."""
    event = GuardianEvent()
    event.path = b"/tmp/output.json"
    assert event.path == b"/tmp/output.json"


def test_guardian_event_all_fields_set(sample_event):
    """Test that the sample_event fixture has correctly populated all expected fields."""
    assert sample_event.pid == 12345
    assert sample_event.syscall == 4
    assert sample_event.comm == b"python3"
    assert sample_event.path == b"/tmp/output.json"
