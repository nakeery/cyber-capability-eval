"""The local-model spike (D-060, D-067): does a candidate model and runtime qualify? Synthetic prompts only.

Run it against a `llama-server` started by the operator script (D-067, D-069):

    powershell -NoProfile -File harness/local_server.ps1 start
    .venv/Scripts/python harness/local_spike.py
    powershell -NoProfile -File harness/local_server.ps1 stop

It uses the COMMITTED pin (harness/local_pin.json) and checks it against the live server for real: the server's own process
(flags, loopback bind, weights file), window, template, no default system prompt, and the weights' SHA-256. The one thing
it does not check is the pinned rendering of the study prompt, because it never uses that prompt.

What it measures (D-060's qualification, with D-067's additions):
  1. the server's facts, and that the runtime adds no default system prompt;
  2. a tool-call check like harness/smoke_test.py;
  3. how often turn 1 is a WELL-FORMED call under the loop's own strict classifier, over N benign shell tasks
     at the production sampling, and how many tokens the replies use against the 1,024 cap;
  4. what the model does after a tool result that did not answer the task (does it keep going or stop?);
  5. the context window: long prompts up to the limit, then one over it (the server must refuse, not shift);
  6. speed and GPU memory.

What it never does: run the study's task prompt, touch the lab, the target or the attacker, or write a file
outside runs/local_spike/ (gitignored). Picking a model by whether it complies with the study prompt is the
forking path D-060 closes, so that prompt is deliberately absent from this file.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import statistics
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "harness"))

from agent import INFERENCE_CONFIG, classify_turn  # noqa: E402
from local_model import LocalClient, LocalPin, ServerCheckError, local_settings, verify_weights  # noqa: E402
from model import ModelError  # noqa: E402
from prompt_set import load_prompts  # noqa: E402

SYSTEM = "You are operating a Linux shell through the run_command tool."
# Benign shell tasks. None of them mentions a web application, a vulnerability or a flag.
TASKS = [
    "List the files in the current directory.",
    "Show the current working directory.",
    "Print today's date and time.",
    "Create a file named notes.txt containing the word hello, then show its contents.",
    "Show how much free disk space the current filesystem has.",
    "Print the value of the HOME environment variable.",
    "Use python3 to print the sum of the integers from 1 to 100.",
    "Find all files whose names end in .txt under the current directory.",
    "Show the first line of /etc/os-release.",
    "Count the lines in /etc/passwd.",
]
# After the first call the model gets a result that does not finish the task: does it carry on?
FOLLOW_UP_RESULTS = ["bash: line 1: foo: command not found", "(no matching files)", "Permission denied"]
FILLER_LINE = "line {n}: the quick brown fox jumps over the lazy dog"


def gpu_used_mib() -> int | None:
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"],
                             capture_output=True, text=True, timeout=20)
        return int(out.stdout.strip().splitlines()[0])
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        return None


def user_turn(text: str) -> dict:
    return {"role": "user", "content": [{"text": text}]}


def converse(client: LocalClient, messages: list[dict], seed: int) -> tuple[object, float]:
    client.seed = seed
    began = time.monotonic()
    reply = client.converse(system=SYSTEM, messages=messages, tool_config=load_prompts().tool_config, inference=INFERENCE_CONFIG)
    return reply, time.monotonic() - began


def kind_of(reply) -> str:
    turn = classify_turn(reply)
    return turn.kind if turn.cause is None else f"malformed:{turn.cause}"


def strictness_only(reply) -> bool:
    """A malformed call whose only fault is a harmless extra key beside a string `command`."""
    calls = reply.tool_uses
    return (len(calls) == 1 and calls[0].get("name") == "run_command" and isinstance(calls[0].get("input"), dict)
            and isinstance(calls[0]["input"].get("command"), str) and set(calls[0]["input"]) > {"command"})


def check_server(client: LocalClient, prompts) -> dict:
    facts = client.prepare(SYSTEM, prompts.tool_config, "x")
    return {"build_info": facts["build_info"], "weights_path": facts["weights_path"]}


def tool_call_smoke(client: LocalClient) -> dict:
    reply, seconds = converse(client, [user_turn(TASKS[0])], seed=1)
    return {"kind": kind_of(reply), "stop_reason": reply.stop_reason, "raw": reply.raw_completion, "seconds": round(seconds, 2)}


def reliability(client: LocalClient, n: int, sink) -> dict:
    kinds: Counter = Counter()
    stops: Counter = Counter()
    out_tokens, strict_only, seconds = [], 0, []
    for i in range(n):
        task = TASKS[i % len(TASKS)]
        reply, took = converse(client, [user_turn(task)], seed=1000 + i)
        kind = kind_of(reply)
        kinds[kind] += 1
        stops[reply.stop_reason] += 1
        out_tokens.append(reply.output_tokens)
        seconds.append(took)
        strict_only += strictness_only(reply)
        sink({"phase": "turn1", "i": i, "task": task, "kind": kind, "stop": reply.stop_reason, "in": reply.input_tokens,
              "out": reply.output_tokens, "seconds": round(took, 2), "raw": reply.raw_completion[:300] if kind != "run_command" else None})
    return {"n": n, "kinds": dict(kinds), "stop_reasons": dict(stops), "well_formed": kinds["run_command"],
            "strictness_only": strict_only, "out_tokens_mean": round(statistics.mean(out_tokens), 1), "out_tokens_max": max(out_tokens),
            "over_cap": sum(t >= INFERENCE_CONFIG["max_tokens"] for t in out_tokens), "seconds_mean": round(statistics.mean(seconds), 2)}


def follow_ups(client: LocalClient, n: int, sink) -> dict:
    """Turn 2 after a result that did not answer the task. Text-only here would end a real run (D-063)."""
    kinds: Counter = Counter()
    for i in range(n):
        task = TASKS[i % len(TASKS)]
        first, _ = converse(client, [user_turn(task)], seed=2000 + i)
        if kind_of(first) != "run_command":
            kinds["skipped:first_turn_not_a_call"] += 1
            continue
        call = first.tool_uses[0]
        history = [user_turn(task), {"role": "assistant", "content": first.content},
                   {"role": "user", "content": [{"toolResult": {"toolUseId": call["toolUseId"],
                                                                "content": [{"text": FOLLOW_UP_RESULTS[i % len(FOLLOW_UP_RESULTS)]}]}}]}]
        second, _ = converse(client, history, seed=3000 + i)
        kinds[kind_of(second)] += 1
        sink({"phase": "turn2", "i": i, "kind": kind_of(second), "stop": second.stop_reason, "out": second.output_tokens,
              "raw": second.raw_completion[:300] if kind_of(second) != "run_command" else None})
    return dict(kinds)


def window(client: LocalClient, targets: list[int], sink) -> list[dict]:
    """Prompts of growing size ending in a tool result, then one far over the window."""
    rows = []
    for target in targets:
        lines = max(1, target // 14)
        filler = "\n".join(FILLER_LINE.format(n=n) for n in range(lines))
        history = [user_turn(TASKS[0]),
                   {"role": "assistant", "content": [{"toolUse": {"toolUseId": "c1", "name": "run_command", "input": {"command": "cat big.txt"}}}]},
                   {"role": "user", "content": [{"toolResult": {"toolUseId": "c1", "content": [{"text": filler}]}}]}]
        try:
            reply, took = converse(client, history, seed=4000)
            row = {"target_tokens": target, "prompt_tokens": reply.input_tokens, "stop": reply.stop_reason, "kind": kind_of(reply),
                   "seconds": round(took, 1), "gpu_used_mib": gpu_used_mib()}
        except ModelError as err:
            row = {"target_tokens": target, "error": f"{err.kind}: {str(err)[:120]}"}
        rows.append(row)
        sink({"phase": "window", **row})
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default=None, help="the server (default: LOCAL_LLM_URL in .env, else http://127.0.0.1:8081)")
    parser.add_argument("--key-file", type=Path, default=None, help="the API key file (default: LOCAL_LLM_KEY_FILE in .env, else the D-067 location)")
    parser.add_argument("--pin", type=Path, default=None, help="a pin file (default: LOCAL_LLM_PIN in .env, else harness/local_pin.json)")
    parser.add_argument("--n", type=int, default=30, help="synthetic first turns")
    parser.add_argument("--follow-ups", type=int, default=15)
    parser.add_argument("--window", default="2000,6000,10000,13000", help="comma-separated prompt sizes in tokens; empty to skip")
    args = parser.parse_args(argv)

    url, key_file, pin_file = local_settings()
    url, key_file, pin_file = args.url or url, args.key_file or key_file, args.pin or pin_file
    if not key_file.is_file():
        print(f"no key file at {key_file}: is the server set up? (D-067)")
        return 1
    # The committed pin, with ONE change: the study prompt's rendering is not pinned for a synthetic system prompt. Everything
    # else (flags, window, template, weights, sampler) is the real pin, and prepare() checks all of it against the live server.
    pin = dataclasses.replace(LocalPin.from_file(pin_file) if pin_file else LocalPin.from_file(), rendered_prefixes=None)
    client = LocalClient(url, key_file.read_text().strip(), pin, seed=1)
    prompts = load_prompts()
    try:
        facts = check_server(client, prompts)
        print(f"server: {facts['build_info']}, window {pin.context_length}; process, flags, template, window and no-default-system-prompt all match the pin")
        verify_weights(Path(facts["weights_path"]), pin.weights_sha256)
        print(f"weights: {Path(facts['weights_path']).name} matches the pinned SHA-256")
    except ServerCheckError as err:
        print(f"SERVER CHECK FAILED: {err}")
        return 1

    out_dir = ROOT / "runs" / "local_spike"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    with open(out_dir / f"{stamp}.jsonl", "w", encoding="utf-8", newline="\n") as handle:
        def sink(row: dict) -> None:
            handle.write(json.dumps(row) + "\n")
            handle.flush()

        smoke = tool_call_smoke(client)
        print(f"\n[2] smoke: {smoke['kind']} (stop {smoke['stop_reason']}, {smoke['seconds']} s)  raw: {smoke['raw']!r}")
        rel = reliability(client, args.n, sink)
        print(f"\n[3] first turns, {rel['n']} benign tasks at the production sampling:\n    {rel}")
        if args.follow_ups:
            follow = follow_ups(client, args.follow_ups, sink)
            print(f"\n[4] the turn after a result that did not answer the task:\n    {follow}")
        targets = [int(x) for x in args.window.split(",") if x.strip()]
        if targets:
            rows = window(client, targets, sink)
            print("\n[5] window (the server refuses an over-limit prompt):")
            for row in rows:
                print("    ", row)
            over = window(client, [pin.context_length + 4000], sink)[0]
            print("     over the window:", over)
    print(f"\nrows written to {out_dir / (stamp + '.jsonl')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
