# Security Policy

> **llm-ebpf-guardian** operates at the kernel boundary via eBPF and is designed
> to *improve* security for LLM-generated code. We take vulnerabilities in this
> project especially seriously — a flaw here could undermine the very sandbox it
> provides.

---

## Supported Versions

Only the latest release on `main` receives security patches.
Pre-release branches (`develop`, `phase-*`) are experimental and unsupported.

| Version     | Supported          |
| ----------- | ------------------ |
| `main` (latest tag) | ✅ |
| Older tags  | ❌                 |
| `develop`   | ❌ (experimental)  |
| `phase-*`   | ❌ (experimental)  |

---

## Scope

The following are **in scope** for security reports:

- **eBPF probe bypass** — a way for a monitored process to evade syscall interception in `guardian.bpf.c`
- **Privilege escalation** — exploiting the loader or scorer to gain capabilities beyond what is intended
- **Policy engine bypass** — tricking `scorer.py` into producing a permissive profile for a malicious task prompt (prompt injection against the Ollama query)
- **Ring buffer poisoning** — a monitored process manipulating events written to the BPF ring buffer
- **Denial of service** — crashing or hanging `loader.py` / `scorer.py` such that the sandbox stops enforcing policy
- **Dependency vulnerabilities** — critical CVEs in `pyroute2`, `ollama`, or other packages in `requirements.txt` that affect Guardian's security posture

The following are **out of scope**:

- Vulnerabilities in the Ollama model itself or its weights
- Issues that require physical access to the machine
- Social engineering
- Findings from automated scanners with no demonstrated impact

---

## Reporting a Vulnerability

**Please do not open a public GitHub Issue for security vulnerabilities.**

Use GitHub's private vulnerability reporting instead:

1. Go to the [Security tab](../../security) of this repository
2. Click **"Report a vulnerability"**
3. Fill in the details described below

If private reporting is unavailable, email the maintainer directly at the
address listed on the [GitHub profile](https://github.com/radeshgovind-2005).
Encrypt your message with the PGP key linked there if possible.

### What to include

A useful report contains:

- **Description** — what the vulnerability is and what an attacker could achieve
- **Component** — which file(s) are affected (`guardian.bpf.c`, `loader.py`, `scorer.py`, etc.)
- **Reproduction steps** — the minimal command sequence or code to trigger the issue
- **Impact** — realistic worst-case outcome (e.g. "monitored process can call `execve` without emitting an event")
- **Suggested fix** — optional, but appreciated

### Response timeline

| Milestone | Target |
| --------- | ------ |
| Acknowledgement | Within **48 hours** |
| Triage & severity assessment | Within **5 business days** |
| Status update | Every **7 days** until resolved |
| Patch release (critical) | Within **14 days** of confirmation |
| Patch release (moderate) | Within **30 days** of confirmation |

### What to expect

- You will receive an acknowledgement with a tracking reference
- We will confirm whether the report is accepted or declined, with reasoning
- Accepted vulnerabilities will be fixed on a private branch and released with a security advisory
- You will be credited in the advisory unless you request otherwise
- We do not currently offer a bug bounty, but we will publicly acknowledge your contribution

---

## Security Design Notes

For reviewers and contributors, the key security invariants this project relies on:

1. **The eBPF verifier** is the first line of defence — the probe cannot crash the kernel or access arbitrary memory
2. **`target_pid = 0` is test mode only** — production deployments must always set a specific PID
3. **Ollama runs on the host, not inside the sandbox** — the scoring decision is made outside the monitored process's reach
4. **`SIGKILL` is the enforcement action** — we do not use `SIGTERM`, which the process can catch and ignore
5. **The ring buffer is kernel-managed** — userspace cannot write to it, only read