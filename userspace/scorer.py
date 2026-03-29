#!/usr/bin/env python3
"""
userspace/scorer.py — Phase 3: Ollama-backed anomaly scoring

Given the original task prompt and a stream of syscall events,
the scorer:
  1. Asks Ollama to produce the expected syscall profile for the task
  2. Scores each incoming event against that profile
  3. Returns a running anomaly score to the policy engine

Run Ollama on your host Mac:
    ollama pull llama3.2   (or mistral, phi3, gemma2, etc.)
    ollama serve           (starts on localhost:11434)

The Docker devcontainer forwards port 11434, so this code reaches the
host's Ollama from inside the container at http://host.docker.internal:11434
"""

import json
from dataclasses import dataclass, field
from typing import Optional

import ollama

# ── Configuration ─────────────────────────────────────────────────────────────

OLLAMA_HOST  = "http://host.docker.internal:11434"
OLLAMA_MODEL = "llama3.2"   # swap for any model you have pulled

# Anomaly score weights — tuned for a conservative security posture.
# Increase a weight to make Guardian more aggressive about blocking.
SCORE_WEIGHTS = {
    "execve":   40,
    "socket":   40,
    "connect":  60,
    "openat":   10,   # only unexpected paths get scored
    "ptrace":  100,   # always maximum — no legitimate use
    "mount":   100,   # always maximum
}

BLOCK_THRESHOLD = 100   # score at which policy engine triggers SIGKILL


# ── Task profile ──────────────────────────────────────────────────────────────

@dataclass
class TaskProfile:
    """Expected syscall behaviour derived from the LLM task prompt."""
    task:             str
    expected_syscalls: list[str]  = field(default_factory=list)
    allowed_paths:     list[str]  = field(default_factory=list)  # openat whitelist
    rationale:         str        = ""


def build_profile(task: str) -> TaskProfile:
    """
    Ask Ollama what syscalls a process legitimately needs for this task.

    Returns a TaskProfile with expected_syscalls and allowed_paths.
    Falls back to a strict deny-all profile on Ollama errors.
    """
    client = ollama.Client(host=OLLAMA_HOST)

    prompt = f"""You are a Linux security expert. A process will execute the following task:

TASK: {task}

List ONLY the Linux syscalls this process legitimately needs.
Choose from: execve, socket, connect, openat, ptrace, mount

Also list the file path prefixes the process may legitimately open (for openat).

Respond with JSON only, no explanation:
{{
  "expected_syscalls": ["openat", "write", "close"],
  "allowed_path_prefixes": ["/tmp/", "/proc/self/"],
  "rationale": "one sentence"
}}"""

    try:
        response = client.chat(
            model=OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
            format="json",
        )
        raw = response["message"]["content"]
        data = json.loads(raw)
        return TaskProfile(
            task=task,
            expected_syscalls=data.get("expected_syscalls", []),
            allowed_paths=data.get("allowed_path_prefixes", []),
            rationale=data.get("rationale", ""),
        )
    except Exception as exc:
        print(f"[scorer] Ollama error — using deny-all profile: {exc}")
        return TaskProfile(task=task, expected_syscalls=["openat"])


# ── Scoring ───────────────────────────────────────────────────────────────────

@dataclass
class ScoringSession:
    profile:       TaskProfile
    score:         int = 0
    event_log:     list = field(default_factory=list)

    def score_event(self, syscall_name: str, path: str = "") -> Optional[str]:
        """
        Score a single syscall event.
        Returns None if benign, or an alert string if anomalous.
        """
        # ptrace and mount are always blocked regardless of profile
        if syscall_name in ("ptrace", "mount"):
            self.score += SCORE_WEIGHTS[syscall_name]
            return f"BLOCK syscall={syscall_name} score={self.score}"

        # openat: check path is in the allowlist
        if syscall_name == "openat":
            allowed = any(path.startswith(p) for p in self.profile.allowed_paths)
            if not allowed:
                weight = SCORE_WEIGHTS["openat"]
                self.score += weight
                return f"ALERT openat outside allowed paths: {path} score={self.score}"
            return None

        # all other syscalls: check against expected profile
        if syscall_name not in self.profile.expected_syscalls:
            weight = SCORE_WEIGHTS.get(syscall_name, 30)
            self.score += weight
            alert = f"ALERT unexpected syscall={syscall_name} score={self.score}"
            if self.score >= BLOCK_THRESHOLD:
                return f"BLOCK {alert} THRESHOLD BREACHED"
            return alert

        return None


# ── Demo ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    task = "write a JSON config file to /tmp/output.json"
    print(f"Building profile for: '{task}'")
    print(f"Connecting to Ollama at {OLLAMA_HOST} using model {OLLAMA_MODEL}\n")

    profile = build_profile(task)
    print(f"Expected syscalls: {profile.expected_syscalls}")
    print(f"Allowed paths:     {profile.allowed_paths}")
    print(f"Rationale:         {profile.rationale}\n")

    session = ScoringSession(profile=profile)

    test_events = [
        ("openat",  "/tmp/output.json"),   # allowed  # nosec B108
        ("openat",  "/etc/passwd"),        # suspicious
        ("socket",  ""),                   # unexpected
        ("connect", ""),                   # unexpected — should breach threshold
        ("ptrace",  ""),                   # always blocked
    ]

    print("Scoring test events:")
    for syscall, path in test_events:
        result = session.score_event(syscall, path)
        status = result if result else "ok"
        print(f"  {syscall:8} {path:30} → {status}")