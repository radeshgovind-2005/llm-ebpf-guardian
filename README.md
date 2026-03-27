# llm-ebpf-guardian

Kernel-level sandboxing and observability for LLM-generated code. Uses eBPF to intercept syscalls at the kernel boundary, detecting and blocking unauthorized behavior from AI agent processes — with near-zero performance overhead.

The core risk in agentic AI isn't the model hallucinating text. It's the model generating code that runs, and that code doing something the operator never intended. This project enforces a runtime security boundary between what the agent was *asked* to do and what the process is *actually doing*.

---

## What it does

Attaches eBPF probes to a target process running LLM-generated code and monitors its syscall behavior in real time:

```
LLM generates code → process spawns → eBPF probe attaches
                                              ↓
                              syscall stream: execve, socket, connect, openat ...
                                              ↓
                              userspace loader: correlate with original prompt
                                              ↓
                              anomaly score + block / alert / log
```

An agent tasked with "write a config file" should be calling `openat` and `write`. If it calls `socket` and `connect`, that's an intent-to-action mismatch — Guardian flags it and optionally kills the process.

---

## Monitored syscalls

| Syscall | Risk | Default action |
|---|---|---|
| `execve` | Spawning child processes | Alert |
| `socket` | Opening network sockets | Block if task is file-only |
| `connect` | Outbound network connections | Block if task is file-only |
| `openat` | File access outside working dir | Alert |
| `ptrace` | Debugging / process injection | Block always |
| `mount` | Filesystem manipulation | Block always |

---

## Anomaly scoring

Each process gets a task profile derived from the original LLM prompt. Guardian correlates live syscall behavior against that profile and computes a running anomaly score:

```
task: "write a JSON config file to /tmp/output.json"
expected syscalls: openat, write, close
unexpected: socket → score += 40
unexpected: connect → score += 60 → threshold breached → SIGKILL
```

Scores and events are emitted in real time — low latency, suitable for high-throughput inference clusters.

---

## Stack

| Layer | Technology |
|---|---|
| Kernel probes | C (eBPF programs via libbpf) |
| Userspace loader | Python (loads and attaches eBPF programs) |
| Syscall maps | BPF hash maps (kernel → userspace ring buffer) |
| Event output | Perf event buffer → Python consumer |
| Kernel requirement | Linux 5.x+ with BTF (BPF Type Format) support |

---

## Project structure

```
llm-ebpf-guardian/
├── kernel/
│   ├── guardian.bpf.c       # eBPF probe — syscall interception logic
│   └── guardian.h           # Shared structs between kernel and userspace
├── userspace/
│   ├── loader.py            # Attaches eBPF programs, reads perf buffer
│   ├── scorer.py            # Anomaly scoring and task profile matching
│   └── policy.py            # Block/alert/log decision engine
├── profiles/
│   └── default_policy.yaml  # Syscall allowlists per task type
├── decisions.md
├── requirements.txt
└── README.md
```

---

## Requirements

**System:**
- Linux kernel 5.8+ with BTF enabled (`/sys/kernel/btf/vmlinux` must exist)
- Root or `CAP_BPF` + `CAP_PERFMON` capabilities

**Python:**
```
bcc
pyroute2
```

Or with libbpf directly:
```
libbpf-python
```

---

## Architectural decisions

Full reasoning in [`decisions.md`](./decisions.md). Key choices:

- **Why eBPF over seccomp?** — seccomp is a static allowlist set at process start. eBPF is dynamic — you can attach, detach, and update policy without restarting the process. Also gives you visibility into *what* happened, not just *whether* to block it.
- **Why libbpf over BCC?** — BCC compiles eBPF at runtime and requires kernel headers on the host. libbpf uses CO-RE (Compile Once, Run Everywhere) — the probe compiles once and runs across kernel versions. Lower friction for deployment.
- **Why Python userspace?** — The hot path is kernel-side in C. The userspace loader just reads from a ring buffer and applies scoring logic. Python is fast enough for that and keeps the anomaly scoring readable.

---

## References

- [eBPF documentation](https://ebpf.io)
- [libbpf](https://github.com/libbpf/libbpf)
- [BCC tools](https://github.com/iovisor/bcc)
- [Linux kernel BTF](https://www.kernel.org/doc/html/latest/bpf/btf.html)