"""Seed replay: a diagnostic, not study data. Writes nothing under runs/ or harness/.

Rebuild the conversation a recorded run had at step k (from its steps.jsonl), send it to the live local server with
the run's own seed and then with other seeds, and see whether the model's command changes. It uses the harness's own
client, message conversion, parser and classifier, so only the seed differs from a real turn.

    BASH_EXE=<path to bash.exe> python seed_replay.py <repo root> <run id> <steps, e.g. 1,2,5,15,30> <number of other seeds>

Prints labels, counts and verdicts only, never a command. Labels: R = the command the run actually sent at that
step; A, B, C... = other distinct commands; T = a text-only turn; M = a malformed turn.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(sys.argv[1])
RUN = ROOT / "runs" / sys.argv[2]
KS = [int(x) for x in sys.argv[3].split(",")]
N_OTHER = int(sys.argv[4])
BASH = os.environ["BASH_EXE"]

sys.path.insert(0, str(ROOT / "harness"))
from agent import INFERENCE_CONFIG, classify_turn          # noqa: E402
from local_model import LocalClient, LocalPin, local_settings  # noqa: E402
from prompt_set import load_prompts                          # noqa: E402

if (ROOT / "runs" / ".lab.lock").exists():
    sys.exit("a harness run holds runs/.lab.lock: not starting (the server has one slot)")

steps = [json.loads(line) for line in (RUN / "steps.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
manifest = json.loads((RUN / "manifest.json").read_text(encoding="utf-8"))
condition = manifest["condition"]
original_seed = manifest["local_runtime"]["seed"]
prompts = load_prompts()
url, key_file, pin_file = local_settings()
pin = LocalPin.from_file(pin_file) if pin_file else LocalPin.from_file()
key = key_file.read_text().strip()
system = prompts.system_text(condition)

print(f"run {RUN.name[:8]}  variant {manifest['variant']}  condition {condition}  original seed {original_seed}  "
      f"sampling {INFERENCE_CONFIG}", flush=True)
# The same check every real run makes: the live server must be the pinned one.
LocalClient(url, key, pin, original_seed).prepare(system, prompts.tool_config, prompts.opening)
print("server matches the pin", flush=True)


def history(k: int) -> list[dict]:
    """The messages the loop held just before it made step k's call."""
    messages = [{"role": "user", "content": [{"text": prompts.opening}]}]
    for i in range(k - 1):
        s = steps[i]
        assert s["tool_name"] == "run_command", f"step {i + 1} was not a command"
        call_id = f"call_{i + 1}"
        blocks = [{"text": s["assistant_text"]}] if (s["assistant_text"] or "").strip() else []
        blocks.append({"toolUse": {"toolUseId": call_id, "name": "run_command", "input": s["tool_input"]}})
        messages.append({"role": "assistant", "content": blocks})
        messages.append({"role": "user", "content": [{"toolResult": {
            "toolUseId": call_id, "content": [{"text": s["output_sent_to_model"]}]}}]})
    return messages


def sample(k: int, seed: int):
    reply = LocalClient(url, key, pin, seed).converse(
        system=system, messages=history(k), tool_config=prompts.tool_config, inference=INFERENCE_CONFIG)
    turn = classify_turn(reply)
    command = turn.tool_use["input"]["command"] if turn.kind == "run_command" else None
    return reply, turn, command


def bash_verdict(command: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, encoding="utf-8", newline="\n") as f:
        f.write(command)
        path = f.name
    try:
        done = subprocess.run([BASH, "-n", path], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20)
    finally:
        os.unlink(path)
    if done.returncode == 0:
        return "parses"
    return "UNBALANCED QUOTE" if "unexpected EOF while looking for matching" in done.stderr else "other syntax error"


SEEDS = [7000 + i for i in range(1, N_OTHER + 1)]
for k in KS:
    recorded = steps[k - 1]
    # The recorded step being replayed need not be a command: it can be the text-only (or malformed) turn
    # that actually ended the run (checking whether THAT repeats under other seeds is the point).
    rec_kind = recorded.get("tool_name") or ("malformed" if recorded.get("tool_call_error") else "text_only")
    rec_cmd = recorded["tool_input"]["command"] if rec_kind == "run_command" else None
    rec_tag = {"run_command": "R", "text_only": "T", "malformed": "M"}[rec_kind]
    labels = {rec_cmd: "R"} if rec_cmd is not None else {}
    letters = iter("ABCDEFGHIJKLMNOPQSUVWXYZ")

    def label(turn, command):
        if turn.kind != "run_command":
            return "T" if turn.kind == "text_only" else "M"
        if command not in labels:
            labels[command] = next(letters)
        return labels[command]

    r1, t1, c1 = sample(k, original_seed)
    r2, t2, c2 = sample(k, original_seed)
    faithful = r1.raw_completion == recorded.get("raw_completion") and r2.raw_completion == recorded.get("raw_completion")
    print(f"\n=== step {k}: recorded outcome was {rec_tag} ({rec_kind}); prompt tokens {r1.input_tokens} "
          f"(recorded {recorded['input_tokens']}, {'match' if r1.input_tokens == recorded['input_tokens'] else 'DIFFER'})",
          flush=True)
    print(f"    original seed, replayed twice: raw completion equals the recorded one: "
          f"{r1.raw_completion == recorded.get('raw_completion')} / {r2.raw_completion == recorded.get('raw_completion')}; "
          f"turn kind equals the recorded one: {t1.kind == rec_kind} / {t2.kind == rec_kind}", flush=True)
    if not faithful:
        print("    WARNING: the replay under the run's OWN seed does not reproduce the recorded completion.\n"
              "    prompts/ (or the server) has changed since this run happened -- the seeds below are not an\n"
              "    isolated test of seed dependency, they are confounded with whatever else changed. Do not\n"
              "    trust the counts that follow for this step.", flush=True)
    seen = []
    for seed in SEEDS:
        reply, turn, command = sample(k, seed)
        seen.append((label(turn, command), command))
    row = " ".join(lab for lab, _ in seen)
    commands = [c for _, c in seen if c is not None]
    n_text_only = sum(1 for lab, _ in seen if lab == "T")
    n_malformed = sum(1 for lab, _ in seen if lab == "M")
    print(f"    {N_OTHER} other seeds -> {row}", flush=True)
    summary = (f"    of {N_OTHER}: {n_text_only} text-only, {n_malformed} malformed, "
               f"{len(commands)} ran a command ({len(set(commands))} distinct)")
    if rec_cmd is not None:
        summary += f"; equal to the recorded command: {sum(1 for c in commands if c == rec_cmd)}"
    print(summary, flush=True)
    for command, lab in labels.items():
        if command is not None and (lab == "R" or command in set(commands)):
            print(f"      {lab}: {bash_verdict(command):<18} single quotes {command.count(chr(39))}, length {len(command)}", flush=True)
print("\ndone", flush=True)
