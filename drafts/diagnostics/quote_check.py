"""Structural check of recorded commands. Prints counts and verdicts only, never a command or its output.

For every run_command step in the newest N runs (or one run, given a run-id prefix): did bash in the
container report an unbalanced quote (`unexpected EOF while looking for matching`)? And does the RECORDED
command, written to a file and checked with `bash -n` on this machine (no docker, no Windows argv in
between), have the same problem?

    BASH_EXE=<path to bash.exe> python quote_check.py <runs dir> <newest N> [run-id prefix]
"""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

RUNS = Path(sys.argv[1])
N = int(sys.argv[2])
BASH = os.environ["BASH_EXE"]

dirs = sorted((d for d in RUNS.iterdir() if d.is_dir()), key=lambda d: d.stat().st_ctime)[-N:]
if len(sys.argv) > 3:                      # an optional run-id prefix picks one run instead of the newest N
    dirs = [d for d in RUNS.iterdir() if d.is_dir() and d.name.startswith(sys.argv[3])]


def bash_n(command: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, encoding="utf-8", newline="\n") as f:
        f.write(command)
        path = f.name
    try:
        done = subprocess.run([BASH, "-n", path], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20)
    finally:
        os.unlink(path)
    err = done.stderr
    if done.returncode == 0:
        return "ok"
    if "unexpected EOF while looking for matching" in err:
        m = re.search(r"matching `(.)'", err)
        return "unbalanced " + (m.group(1) if m else "?")
    return "other-syntax"


for d in dirs:
    manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8")) if (d / "manifest.json").exists() else {}
    print(f"\nrun {d.name[:8]}  variant {manifest.get('variant')}  condition {manifest.get('condition')}  "
          f"ended {manifest.get('termination_reason')}")
    rows = []
    for line in (d / "steps.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        s = json.loads(line)
        if s.get("tool_name") != "run_command" or not s.get("tool_input"):
            rows.append((s["step"], s.get("tool_name") or f"(none: {s.get('tool_call_error') or s.get('stop_reason')})", "", "", "", "", ""))
            continue
        cmd = s["tool_input"]["command"]
        out = s.get("output_full") or ""
        container = "EOF-error" if "unexpected EOF while looking for matching" in out else ("syntax-error" if "syntax error" in out else "-")
        rows.append((s["step"], "run_command", s.get("exit_code"), container, bash_n(cmd),
                     f"sq={cmd.count(chr(39))} dq={cmd.count(chr(34))} bs={cmd.count(chr(92))}",
                     f"len={len(cmd)} nl={cmd.count(chr(10))}"))
    print(f"  {'step':>4}  {'tool':<12} {'exit':>4}  {'in container':<13} {'bash -n on raw':<14} quote counts / size")
    for r in rows:
        print(f"  {r[0]:>4}  {r[1]:<12} {str(r[2]):>4}  {r[3]:<13} {r[4]:<14} {r[5]}  {r[6]}")
    cmds = [r for r in rows if r[1] == "run_command"]
    eof = [r for r in cmds if r[3] == "EOF-error"]
    both = [r for r in eof if r[4].startswith("unbalanced")]
    raw_bad_only = [r for r in cmds if r[3] != "EOF-error" and r[4].startswith("unbalanced")]
    print(f"  SUMMARY: {len(cmds)} commands; {len(eof)} hit the EOF error in the container; "
          f"{len(both)} of those are also unbalanced under bash -n on the raw string; "
          f"{len(eof) - len(both)} errored in the container but parse fine raw (would point at transit); "
          f"{len(raw_bad_only)} unbalanced raw but no container EOF error")
