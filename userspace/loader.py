#!/usr/bin/env python3
"""
userspace/loader.py — Phase 2: load the eBPF probe, read events, stream to scorer

Usage (as root or with CAP_BPF + CAP_PERFMON):
    python3 userspace/loader.py --pid <PID> --task "write a JSON config file"

The loader:
  1. Compiles and loads kernel/guardian.bpf.o into the kernel
  2. Attaches the tracepoints to the target PID
  3. Reads guardian_event structs from the ring buffer in a tight loop
  4. Forwards each event to scorer.py for anomaly scoring
"""

import argparse
import ctypes
import signal
import sys
from pathlib import Path

from rich.console import Console

console = Console()

# ── ctypes mirror of guardian_event from guardian.h ──────────────────────────
# Must match the struct layout in kernel/guardian.h exactly.

TASK_COMM_LEN = 16
PATH_LEN = 128

SYSCALL_NAMES = {
    1: "execve",
    2: "socket",
    3: "connect",
    4: "openat",
    5: "ptrace",
    6: "mount",
}


class GuardianEvent(ctypes.Structure):
    _fields_ = [
        ("timestamp_ns",  ctypes.c_uint64),
        ("pid",           ctypes.c_uint32),
        ("tgid",          ctypes.c_uint32),
        ("uid",           ctypes.c_uint32),
        ("syscall",       ctypes.c_uint32),   # enum syscall_id
        ("comm",          ctypes.c_char * TASK_COMM_LEN),
        ("path",          ctypes.c_char * PATH_LEN),
        ("socket_family", ctypes.c_uint16),
        ("remote_addr",   ctypes.c_uint32),
        ("remote_port",   ctypes.c_uint16),
        ("ret",           ctypes.c_uint32),
    ]


# ── BPF loading ───────────────────────────────────────────────────────────────

def load_bpf(target_pid: int):  # pragma: no cover
    """
    Load guardian.bpf.o and attach tracepoints.
    Returns the BPF object so the caller can keep it alive.

    Phase 1 deliverable: this function should print all six tracepoints
    as 'attached' and not crash.
    """
    try:
        import libbpf  # libbpf-python  (pip install libbpf-python)  # noqa: F401
    except ImportError:
        console.print("[red]libbpf-python not installed. Run: pip install libbpf-python[/red]")
        sys.exit(1)

    bpf_obj_path = Path(__file__).parent.parent / "kernel" / "guardian.bpf.o"
    if not bpf_obj_path.exists():
        console.print(f"[red]Compiled BPF object not found: {bpf_obj_path}[/red]")
        console.print("[yellow]Compile first:[/yellow] clang -g -O2 -target bpf "
                      "-c kernel/guardian.bpf.c -o kernel/guardian.bpf.o")
        sys.exit(1)

    # TODO (Phase 2): replace this stub with real libbpf-python attach calls
    # obj = libbpf.BPFObject(str(bpf_obj_path))
    # obj.load()
    # obj.attach_tracepoint(...)
    console.print(f"[green]✓ BPF object found:[/green] {bpf_obj_path}")
    console.print(f"[green]✓ Would attach to PID:[/green] {target_pid or '(all)'}")
    console.print("[yellow]Phase 2: implement real attach here[/yellow]")
    return None


# ── Event display ─────────────────────────────────────────────────────────────

def print_event(event: GuardianEvent):
    syscall_name = SYSCALL_NAMES.get(event.syscall, f"unknown({event.syscall})")
    comm = event.comm.decode("utf-8", errors="replace").rstrip("\x00")
    path = event.path.decode("utf-8", errors="replace").rstrip("\x00")

    # Colour-code by risk
    colour = {
        "ptrace": "red",
        "mount":  "red",
        "socket": "yellow",
        "connect":"yellow",
        "execve": "cyan",
        "openat": "white",
    }.get(syscall_name, "white")

    console.print(
        f"[{colour}]{syscall_name:8}[/{colour}] "
        f"pid={event.pid:6} comm={comm:16} "
        f"path={path[:60] or '-'}"
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def main():  # pragma: no cover
    parser = argparse.ArgumentParser(description="llm-ebpf-guardian loader")
    parser.add_argument("--pid",  type=int, default=0,
                        help="PID to monitor (0 = all processes, for testing)")
    parser.add_argument("--task", type=str, default="",
                        help="Original LLM task prompt (passed to scorer)")
    args = parser.parse_args()

    console.rule("[bold]llm-ebpf-guardian[/bold]")
    console.print(f"Task: [italic]{args.task or '(none)'}[/italic]")
    console.print(f"Monitoring PID: {args.pid or 'ALL (test mode)'}\n")

    _bpf = load_bpf(args.pid)

    # Graceful shutdown on Ctrl-C
    def _shutdown(sig, frame):
        console.print("\n[bold]Detaching probes. Goodbye.[/bold]")
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)

    console.print("[dim]Waiting for syscall events... (Ctrl-C to stop)[/dim]\n")

    # TODO (Phase 2): replace this with real ring buffer poll loop
    # while True:
    #     bpf.ring_buffer_poll()

    # Stub: simulate a few events so you can test the display code
    import time
    demo_events = [
        (4, b"python3", b"/tmp/output.json"),
        (2, b"python3", b""),
        (3, b"python3", b""),
        (5, b"python3", b""),   # ptrace — should be red
    ]
    for syscall_id, comm, path in demo_events:
        e = GuardianEvent()
        e.pid = 12345
        e.syscall = syscall_id
        e.comm = comm
        e.path = path
        print_event(e)
        time.sleep(0.3)


if __name__ == "__main__":
    main()