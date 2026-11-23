"""Does showing curl's own --help text, instead of the recorded bash error, change the model's NEXT command? A
diagnostic replay against the live local server, not study data: it never touches runs/ or harness/, and it is
not part of the floor check. Prints turn kinds, bash -n verdicts and yes/no structural counts only, never a
command's text.

    BASH_EXE=<path to bash.exe> python help_hint_test.py <repo root> <run id> <step to answer differently> <number of seeds>
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(sys.argv[1])
RUN = ROOT / "runs" / sys.argv[2]
K = int(sys.argv[3])
N = int(sys.argv[4])
BASH = os.environ["BASH_EXE"]

sys.path.insert(0, str(ROOT / "harness"))
from agent import INFERENCE_CONFIG, classify_turn            # noqa: E402
from local_model import LocalClient, LocalPin, local_settings  # noqa: E402
from prompt_set import load_prompts                            # noqa: E402

if (ROOT / "runs" / ".lab.lock").exists():
    sys.exit("a harness run holds runs/.lab.lock: not starting (the server has one slot)")

steps = [json.loads(line) for line in (RUN / "steps.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
manifest = json.loads((RUN / "manifest.json").read_text(encoding="utf-8"))
condition = manifest["condition"]
prompts = load_prompts()
url, key_file, pin_file = local_settings()
pin = LocalPin.from_file(pin_file) if pin_file else LocalPin.from_file()
key = key_file.read_text().strip()
system = prompts.system_text(condition)

help_text = subprocess.run([BASH, "-lc", "curl --help"], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=20).stdout
print("curl --help captured locally:", len(help_text), "chars (generic tool documentation, not attack content)")


def history(k: int, override_last_output: str | None) -> list[dict]:
    """Messages before step k's call, same shape the real loop builds. If given, override_last_output replaces
    step k-1's recorded output_sent_to_model (what the model is shown), nothing else."""
    messages = [{"role": "user", "content": [{"text": prompts.opening}]}]
    for i in range(k - 1):
        s = steps[i]
        call_id = f"call_{i + 1}"
        blocks = [{"text": s["assistant_text"]}] if (s["assistant_text"] or "").strip() else []
        blocks.append({"toolUse": {"toolUseId": call_id, "name": "run_command", "input": s["tool_input"]}})
        messages.append({"role": "assistant", "content": blocks})
        output = override_last_output if (override_last_output is not None and i == k - 2) else s["output_sent_to_model"]
        messages.append({"role": "user", "content": [{"toolResult": {
            "toolUseId": call_id, "content": [{"text": output}]}}]})
    return messages


def bash_n(text: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, encoding="utf-8", newline="\n") as f:
        f.write(text)
        path = f.name
    try:
        done = subprocess.run([BASH, "-n", path], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20)
    finally:
        os.unlink(path)
    if done.returncode == 0:
        return "parses"
    return "unbalanced-quote" if "unexpected EOF while looking for matching" in done.stderr else "other-syntax-error"


def sample(messages: list[dict], seed: int):
    reply = LocalClient(url, key, pin, seed).converse(
        system=system, messages=messages, tool_config=prompts.tool_config, inference=INFERENCE_CONFIG)
    turn = classify_turn(reply)
    command = turn.tool_use["input"]["command"] if turn.kind == "run_command" else None
    return turn.kind, command


seeds = [7000 + i for i in range(1, N + 1)]       # the same seeds the earlier seed-replay check used
baseline = history(K, None)
with_help = history(K, help_text)

print(f"\nrun {RUN.name[:8]}, replaying the call before step {K}, {N} seeds (unchanged baseline vs. help shown instead):")
base_rows = [sample(baseline, s) for s in seeds]
help_rows = [sample(with_help, s) for s in seeds]


def summarize(label: str, rows: list[tuple[str, str | None]]) -> None:
    kinds = [k for k, _ in rows]
    cmds = [c for _, c in rows if c]
    quoted = sum(1 for c in cmds if "'" in c or '"' in c)
    urlencode = sum(1 for c in cmds if "--data-urlencode" in c)
    uses_g = sum(1 for c in cmds if " -G" in f" {c}")
    distinct = len({c for c in cmds})
    parses = sum(1 for c in cmds if bash_n(c) == "parses")
    print(f"  {label}: kinds {kinds}")
    print(f"    of {len(cmds)} command turns: {parses} parse cleanly, {distinct} distinct, "
          f"{quoted} contain a quote character, {urlencode} use --data-urlencode, {uses_g} use -G")


summarize("baseline (recorded error shown)", base_rows)
summarize("with curl --help shown instead", help_rows)
print("\nper-seed match (same command string, baseline vs. with help):",
      [a == b for (_, a), (_, b) in zip(base_rows, help_rows)])
