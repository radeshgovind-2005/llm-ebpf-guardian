"""
tests/integration/test_event_struct.py — binary compatibility tests for GuardianEvent.

Verifies that the ctypes struct layout in loader.py exactly matches what a C compiler
produces for guardian_event in kernel/guardian.h. No kernel or BPF required.
"""

import ctypes
import struct

import pytest

from loader import (
    GuardianEvent,
    PATH_LEN,
    TASK_COMM_LEN,
)

# Authoritative field offsets derived from guardian.h, with natural C alignment:
#   u64  timestamp_ns   → align 8, offset   0
#   u32  pid            → align 4, offset   8
#   u32  tgid           → align 4, offset  12
#   u32  uid            → align 4, offset  16
#   u32  syscall (enum) → align 4, offset  20
#   char comm[16]       → align 1, offset  24
#   char path[128]      → align 1, offset  40
#   u16  socket_family  → align 2, offset 168
#   (2-byte pad)
#   u32  remote_addr    → align 4, offset 172
#   u16  remote_port    → align 2, offset 176
#   (2-byte pad)
#   u32  ret            → align 4, offset 180
#   total              =                   184  (divisible by 8-byte struct align)

EXPECTED_TOTAL_SIZE = 184

EXPECTED_OFFSETS = {
    "timestamp_ns":  0,
    "pid":           8,
    "tgid":         12,
    "uid":          16,
    "syscall":      20,
    "comm":         24,
    "path":         40,
    "socket_family": 168,
    "remote_addr":  172,
    "remote_port":  176,
    "ret":          180,
}


# ── Total struct size ─────────────────────────────────────────────────────────


def test_guardian_event_total_size():
    """Test that GuardianEvent is exactly 184 bytes, matching the C compiler layout."""
    assert ctypes.sizeof(GuardianEvent) == EXPECTED_TOTAL_SIZE


# ── Individual field offsets ──────────────────────────────────────────────────


@pytest.mark.parametrize("field,expected_offset", sorted(EXPECTED_OFFSETS.items(), key=lambda x: x[1]))
def test_guardian_event_field_offset(field, expected_offset):
    """Test that each GuardianEvent field sits at the exact byte offset the C compiler would use."""
    # ctypes CField descriptors expose .offset directly (ctypes.offsetof was never in stdlib)
    actual = getattr(GuardianEvent, field).offset
    assert actual == expected_offset, (
        f"Field '{field}': expected offset {expected_offset}, got {actual}"
    )


# ── Constants match guardian.h ────────────────────────────────────────────────


def test_path_len_matches_guardian_h():
    """Test that PATH_LEN=128 in loader.py matches #define PATH_LEN 128 in guardian.h."""
    assert PATH_LEN == 128


def test_task_comm_len_matches_guardian_h():
    """Test that TASK_COMM_LEN=16 in loader.py matches #define TASK_COMM_LEN 16 in guardian.h."""
    assert TASK_COMM_LEN == 16


def test_comm_array_size_matches_task_comm_len():
    """Test that the comm char array in the struct is sized by TASK_COMM_LEN."""
    # Use the CField descriptor's .size attribute — accessing the field on an instance
    # returns bytes, which has no ctypes size; the descriptor has the right answer.
    assert GuardianEvent.comm.size == TASK_COMM_LEN


def test_path_array_size_matches_path_len():
    """Test that the path char array in the struct is sized by PATH_LEN."""
    assert GuardianEvent.path.size == PATH_LEN


# ── Raw-bytes round-trip (ring buffer simulation) ─────────────────────────────


def test_guardian_event_from_zero_bytes():
    """Test that GuardianEvent can be constructed from an all-zero byte buffer (ring buffer read)."""
    raw = bytes(EXPECTED_TOTAL_SIZE)
    event = GuardianEvent.from_buffer_copy(raw)
    assert event.pid == 0
    assert event.syscall == 0
    assert event.timestamp_ns == 0


def test_guardian_event_pid_from_raw_bytes():
    """Test that pid is correctly parsed from little-endian bytes at offset 8."""
    data = bytearray(EXPECTED_TOTAL_SIZE)
    struct.pack_into("<I", data, EXPECTED_OFFSETS["pid"], 77777)
    event = GuardianEvent.from_buffer_copy(bytes(data))
    assert event.pid == 77777


def test_guardian_event_syscall_from_raw_bytes():
    """Test that syscall enum is correctly parsed from little-endian bytes at offset 20."""
    data = bytearray(EXPECTED_TOTAL_SIZE)
    struct.pack_into("<I", data, EXPECTED_OFFSETS["syscall"], 4)  # SYS_OPENAT = 4
    event = GuardianEvent.from_buffer_copy(bytes(data))
    assert event.syscall == 4


def test_guardian_event_comm_from_raw_bytes():
    """Test that the comm field is correctly read from a simulated ring buffer payload."""
    data = bytearray(EXPECTED_TOTAL_SIZE)
    comm_str = b"python3"
    offset = EXPECTED_OFFSETS["comm"]
    data[offset: offset + len(comm_str)] = comm_str
    event = GuardianEvent.from_buffer_copy(bytes(data))
    # c_char arrays strip the null terminator when accessed as bytes
    assert event.comm == comm_str


def test_guardian_event_path_from_raw_bytes():
    """Test that the path field is correctly read from a simulated ring buffer payload."""
    data = bytearray(EXPECTED_TOTAL_SIZE)
    path_str = b"/tmp/output.json"
    offset = EXPECTED_OFFSETS["path"]
    data[offset: offset + len(path_str)] = path_str
    event = GuardianEvent.from_buffer_copy(bytes(data))
    # c_char arrays strip the null terminator when accessed as bytes
    assert event.path == path_str


def test_guardian_event_timestamp_ns_from_raw_bytes():
    """Test that the u64 timestamp_ns field at offset 0 is correctly deserialized."""
    data = bytearray(EXPECTED_TOTAL_SIZE)
    ts = 1_700_000_000_123_456_789
    struct.pack_into("<Q", data, 0, ts)
    event = GuardianEvent.from_buffer_copy(bytes(data))
    assert event.timestamp_ns == ts
