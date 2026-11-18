"""Run the agent's commands in the attacker container and shape their output (D-062, PLAN.md phase 4).

Two halves. The pure half (`sanitize`, `shape_output`, `StreamCapture`, `classify_timeout`) has no
Docker in it, so the output rules are tested directly. `DockerExecutor` is the thin half that starts
`docker exec` with an argv list (`shell=False`: the agent's command is one argument, never
interpolated into a host shell) and never prints raw output to the operator's terminal.

The loop, not the executor, stamps `started_at` and `ended_at` around `Executor.run` (D-064), so
`run` must not return until the command's process has been stopped.
"""

from __future__ import annotations

import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Protocol

from special_tokens import neutralize

# D-062. Bytes, not characters: the budgets are about what a log or a context window holds.
COMMAND_TIMEOUT_S = 30
STORE_CAP = 1024 * 1024       # at most this much of a command's output is stored (output_full)
SEND_HEAD = 4096              # the model sees the first 4 KiB ...
SEND_TAIL = 4096              # ... and the last 4 KiB around one fixed marker line
SEND_CAP = SEND_HEAD + SEND_TAIL
TAIL_KEEP = SEND_TAIL + 8     # a little extra, so cutting at a character boundary cannot shorten the tail
# After `timeout -s KILL` fires, `docker exec` should return within moments. If it has not by
# then, the client is killed (a process that left the process group can hold the pipe open).
HARD_DEADLINE_GRACE_S = 15

# `timeout` reports 124 (or 128 + SIGKILL when it killed the command with -s KILL). A command can
# also exit with those codes by itself, so the elapsed time must agree before a step counts as timed out.
TIMEOUT_EXIT_CODES = (124, 137)

_ANSI = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"                # CSI sequences (colours, cursor movement)
    r"|\x9b[0-?]*[ -/]*[@-~]"                 # the same, with the single-character 8-bit introducer
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"      # OSC sequences (window titles, hyperlinks)
    r"|\x1b[@-Z\\-_]"                           # two-character escapes
)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")   # everything but "\t" and "\n"


def sanitize(text: str) -> str:
    """What the model is shown of a command's output: ANSI escapes and control characters (all but tab and newline)
    stripped, then special-token text neutralized (D-077: the local server would otherwise read `<|im_end|>` in a tool
    result as a real turn boundary, D-073).

    The order is part of the rule. Neutralizing is LAST, so that stripping cannot build a marker afterwards: with
    `<|im_` + NUL + `end|>`, stripping the NUL is what makes the marker. `output_full` keeps the raw text; this is
    what lands in `output_sent_to_model`, so the record still holds exactly what the model saw (PLAN.md dependency 2)."""
    return neutralize(_CONTROL.sub("", _ANSI.sub("", text)))


def _head(text: str, limit: int) -> str:
    return text.encode("utf-8")[:limit].decode("utf-8", errors="ignore")


def _tail(text: str, limit: int) -> str:
    return text.encode("utf-8")[-limit:].decode("utf-8", errors="ignore")


@dataclass
class ExecResult:
    output_full: str        # decoded with errors="replace", at most STORE_CAP bytes stored
    output_sent: str        # exactly what the model is shown
    truncated: bool
    exit_code: int | None   # None when the client had to be killed
    timed_out: bool


class Executor(Protocol):
    def run(self, command: str) -> ExecResult: ...


def shape_output(head: bytes, tail: bytes, total: int, *, timed_out: bool, marker: str, notice: str
                 ) -> tuple[str, str, bool]:
    """Return (output_full, output_sent, truncated) for one command's captured output.

    `head` is the first min(total, STORE_CAP) bytes, `tail` the last TAIL_KEEP bytes of the whole
    stream. Output over 8 KiB is shown as its first 4 KiB, one marker line and its last 4 KiB: a
    head-only cut could hide a flag near the end of a long page, which would measure the harness
    and not the model (D-062). The timeout notice is appended after whatever output arrived.
    """
    output_full = head.decode("utf-8", errors="replace")
    clean = sanitize(output_full)
    if total > len(head):          # the stream outran the store: the true tail is not in `head`
        shown_tail = sanitize(tail.decode("utf-8", errors="replace"))
        sent = _head(clean, SEND_HEAD) + "\n" + marker + "\n" + _tail(shown_tail, SEND_TAIL)
        truncated = True
    elif len(clean.encode("utf-8")) > SEND_CAP:
        sent = _head(clean, SEND_HEAD) + "\n" + marker + "\n" + _tail(clean, SEND_TAIL)
        truncated = True
    else:
        sent, truncated = clean, False
    if timed_out:
        sent = f"{sent}\n{notice}" if sent else notice
    return output_full, sent, truncated


def classify_timeout(exit_code: int | None, elapsed_s: float, timeout_s: float, *, hard_deadline: bool) -> bool:
    """Did the command run out of time? A killed client always counts; otherwise the exit code
    must be one `timeout` uses AND the command must have run about as long as the limit, so a
    command that merely calls `exit 124` is not mistaken for a timeout."""
    if hard_deadline:
        return True
    return exit_code in TIMEOUT_EXIT_CODES and elapsed_s >= timeout_s - 0.5


class StreamCapture:
    """Keep the first STORE_CAP bytes and a rolling tail of a stream without holding all of it."""

    def __init__(self, store_cap: int = STORE_CAP, tail_keep: int = TAIL_KEEP) -> None:
        self._store_cap, self._tail_keep = store_cap, tail_keep
        self._head, self._tail, self._total = bytearray(), b"", 0
        self._lock = threading.Lock()

    def feed(self, chunk: bytes) -> None:
        with self._lock:
            self._total += len(chunk)
            room = self._store_cap - len(self._head)
            if room > 0:
                self._head += chunk[:room]
            self._tail = (self._tail + chunk)[-self._tail_keep:]

    def pump(self, stream) -> None:
        while chunk := stream.read1(65536):
            self.feed(chunk)

    def snapshot(self) -> tuple[bytes, bytes, int]:
        with self._lock:
            return bytes(self._head), self._tail, self._total


def _popen_kwargs() -> dict:
    # Windows: a Ctrl+C in the operator's terminal reaches every child of the console. A new
    # process group keeps it from interrupting `docker` mid-command, so the harness's own
    # `finally` (which tears the stack down) decides what happens next.
    return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if sys.platform == "win32" else {}


class DockerExecutor:
    """`docker exec` into one attacker container. The container name comes only from the harness."""

    def __init__(self, container: str, *, marker: str, notice: str, timeout_s: int = COMMAND_TIMEOUT_S,
                 grace_s: float = HARD_DEADLINE_GRACE_S, popen=subprocess.Popen) -> None:
        self.container, self.marker, self.notice = container, marker, notice
        self.timeout_s, self.grace_s, self._popen = timeout_s, grace_s, popen

    def argv(self, command: str) -> list[str]:
        # Plain `docker exec` against the container name, never `docker compose exec`: that one
        # starts a plugin child process which survives a kill of the client and holds the pipe.
        return [
            "docker", "exec", "--user", "agent", "--workdir", "/home/agent",
            "--env", "HOME=/home/agent", "--env", "TERM=dumb",
            self.container,
            # `--` ends bash's own options, so a command that starts with "-" is still a command string
            # (without it `bash -lc "-x"` fails with "option requires an argument").
            "timeout", "-s", "KILL", str(self.timeout_s), "bash", "-lc", "--", command,
        ]

    def run(self, command: str) -> ExecResult:
        began = time.monotonic()
        # stdin closed (no -i), so a command that reads it gets EOF instead of hanging; stderr is
        # merged into stdout, which is what run_command promises the model (D-061).
        proc = self._popen(self.argv(command), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, shell=False, **_popen_kwargs())
        capture = StreamCapture()
        reader = threading.Thread(target=capture.pump, args=(proc.stdout,), daemon=True)
        reader.start()
        hard_deadline = False
        try:
            exit_code: int | None = proc.wait(timeout=self.timeout_s + self.grace_s)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            hard_deadline, exit_code = True, None
        reader.join(timeout=5)
        elapsed = time.monotonic() - began
        timed_out = classify_timeout(exit_code, elapsed, self.timeout_s, hard_deadline=hard_deadline)
        head, tail, total = capture.snapshot()
        full, sent, truncated = shape_output(head, tail, total, timed_out=timed_out,
                                             marker=self.marker, notice=self.notice)
        return ExecResult(full, sent, truncated, exit_code, timed_out)
