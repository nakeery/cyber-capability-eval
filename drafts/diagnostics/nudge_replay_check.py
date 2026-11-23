"""Does nudging a text-only reply with a fixed "continue" message, instead of ending the run, actually get
the model to call a tool -- and after how many tries? A diagnostic for a NOT-YET-BUILT harness change
(tolerate up to N consecutive text-only replies before giving up, instead of today's N=1). Writes nothing
under runs/ or harness/, never touches the lab.

Each trial uses ONE seed across every attempt within it, re-sent on every nudge -- this matches how the real
harness actually works (harness/local_model.py sends the same `self.seed` on every request in a run; the
earlier seed-reuse investigation in drafts/diagnostics/log.md established this), so the test is faithful to
what would really happen if this were built, not an idealized fresh-randomness-per-try version.

    BASH_EXE=<unused, kept for parity> python nudge_replay_check.py <repo root> <run id> <step> \
        <number of trial seeds> [max nudges, default 4]

Prints outcomes and attempt counts only, never a command's text.
"""
import json
import sys
from pathlib import Path

ROOT = Path(sys.argv[1])
RUN = ROOT / "runs" / sys.argv[2]
K = int(sys.argv[3])
N_TRIALS = int(sys.argv[4])
MAX_NUDGES = int(sys.argv[5]) if len(sys.argv) > 5 else 4   # N: the number of consecutive text-only
                                                              # replies that, once reached, still ends the run
NUDGE_TEXT = "continue"

sys.path.insert(0, str(ROOT / "harness"))
from agent import INFERENCE_CONFIG, classify_turn            # noqa: E402
from local_model import LocalClient, LocalPin, local_settings  # noqa: E402
from prompt_set import load_prompts                            # noqa: E402

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

print(f"run {RUN.name[:8]}  variant {manifest['variant']}  condition {condition}  step {K}  "
      f"nudge={NUDGE_TEXT!r}  max_nudges(N)={MAX_NUDGES}", flush=True)
LocalClient(url, key, pin, original_seed).prepare(system, prompts.tool_config, prompts.opening)
print("server matches the pin", flush=True)


def history(k: int) -> list[dict]:
    """The messages the loop held just before it made step k's call -- same shape as seed_replay.py."""
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


def call(messages: list[dict], seed: int):
    reply = LocalClient(url, key, pin, seed).converse(
        system=system, messages=messages, tool_config=prompts.tool_config, inference=INFERENCE_CONFIG)
    return reply, classify_turn(reply)


# Fidelity check: does the recorded ending itself still reproduce under its own seed? If not, prompts/ or
# the server has drifted since this run happened, and nothing below is trustworthy -- same guard as
# seed_replay.py, run first and separate from the trial seeds.
recorded = steps[K - 1]
base = history(K)
check_reply, check_turn = call(base, original_seed)
faithful = check_reply.raw_completion == recorded.get("raw_completion")
print(f"fidelity check (own seed, no nudge): raw completion matches recorded = {faithful}", flush=True)
if not faithful:
    print("WARNING: prompts/ (or the server) has changed since this run happened. The trials below are\n"
          "         not an isolated test -- do not trust their counts.", flush=True)

outcomes = []   # (resolved_kind, attempts_used) per trial; resolved_kind in run_command/submit_flag/malformed/
                # provider_block/window_exceeded/empty_reply/exhausted
TRIAL_SEEDS = [8000 + i for i in range(1, N_TRIALS + 1)]
for seed in TRIAL_SEEDS:
    messages = list(base)
    attempt = 1
    while True:
        reply, turn = call(messages, seed)
        if turn.kind in ("run_command", "submit_flag"):
            outcomes.append((turn.kind, attempt))
            break
        if turn.kind == "text_only" and not reply.content:
            outcomes.append(("empty_reply", attempt))      # can't append an empty assistant turn; stop here
            break
        if turn.kind != "text_only":
            outcomes.append((turn.kind, attempt))           # malformed / provider_block / window_exceeded
            break
        if attempt >= MAX_NUDGES:
            outcomes.append(("exhausted", attempt))
            break
        messages = messages + [{"role": "assistant", "content": reply.content},
                                {"role": "user", "content": [{"text": NUDGE_TEXT}]}]
        attempt += 1
    print(f"  seed {seed}: {outcomes[-1][0]} at attempt {outcomes[-1][1]} "
          f"({outcomes[-1][1] - 1} nudge(s) sent)", flush=True)

print(f"\n{N_TRIALS} trials:", flush=True)
resolved = [a for kind, a in outcomes if kind in ("run_command", "submit_flag")]
exhausted = sum(1 for kind, _ in outcomes if kind == "exhausted")
other = [kind for kind, _ in outcomes if kind not in ("run_command", "submit_flag", "exhausted")]
print(f"  resolved into a real call: {len(resolved)} of {N_TRIALS}"
      + (f" (attempts used: {sorted(resolved)})" if resolved else ""), flush=True)
print(f"  exhausted all {MAX_NUDGES} without ever calling: {exhausted} of {N_TRIALS}", flush=True)
if other:
    print(f"  other outcomes: {other}", flush=True)
print("\ndone", flush=True)
