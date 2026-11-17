"""Measure how often Bedrock's content filter blocks the model's FIRST reply (D-065, open item 1).

The real runs showed `stop_reason: content_filtered` with zero output tokens on turn 1, and a three-call
synthetic check suggested the hint sentence triggers it. Three calls cannot tell "always" from "sometimes",
so this sends N independent first turns per cell and reports the blocked rate with a Wilson 95% interval.

    .venv/Scripts/python harness/filter_probe.py --n 30                # Nova Micro, both conditions
    .venv/Scripts/python harness/filter_probe.py --n 30 --models micro,pro

What it is, exactly: the committed system text for each condition plus the committed opening message and
tool schemas, at the production sampling settings, through the same `BedrockClient.converse` the harness
uses (so the scoped-identity check, retries and error classification are identical). One turn only: no lab,
no Docker, no tool is ever run. It changes no committed file and does not touch the prompt.

What it is not: a per-RUN block rate. A turn-1 probe cannot see a block on turn 5. That needs real runs.

The two conditions are interleaved call by call (no_hint, hint, no_hint, hint, ...), so a change in the
filter over the minutes this takes cannot look like a treatment effect. Rows go to a JSONL file under the
gitignored runs/ and hold no model text: only the stop reason, token counts, request id, timing and the
KIND of the first content block.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "harness"))

from agent import INFERENCE_CONFIG  # noqa: E402  (production sampling: one definition, so it cannot drift)
from model import ModelClient, ModelError, bedrock_from_env  # noqa: E402
from prompt_set import CONDITIONS, Prompts, load_prompts  # noqa: E402

BLOCKED = "content_filtered"
MODEL_KEYS = {"micro": "NOVA_MICRO_MODEL_ID", "pro": "NOVA_PRO_MODEL_ID"}
# US dollars per million tokens (input, output), from AWS blog posts, NOT the pricing page (DECISIONS.md D-016
# agrees with them). Only for the printed estimate; check the pricing page before budgeting on it.
PRICES = {"micro": (0.035, 0.14), "pro": (0.80, 3.20)}
MAX_CONSECUTIVE_ERRORS = 5       # a probe that cannot reach the API should stop, not record 60 errors


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """The Wilson score interval for a proportion. Unlike the plain normal interval it stays inside 0..1 and
    is honest at the extremes: 0 of 30 is "up to about 11%", not "exactly 0%"."""
    if total == 0:
        return 0.0, 1.0
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    # At the extremes the bound is exactly 0 (no successes) or exactly 1 (all of them); floating point leaves
    # 1e-16 of residue, which would put the estimate outside its own interval.
    low = 0.0 if successes == 0 else max(0.0, centre - half)
    high = 1.0 if successes == total else min(1.0, centre + half)
    return low, high


def first_block_kind(content: list[dict]) -> str:
    """What the reply began with, without keeping any of its text."""
    if not content:
        return "empty"
    first = content[0]
    if "toolUse" in first:
        return f"toolUse:{first['toolUse'].get('name')}"
    return "text" if "text" in first else "other"


def probe_once(client: ModelClient, prompts: Prompts, condition: str) -> dict:
    """One first turn: the committed prompt for `condition` and nothing else."""
    began = time.monotonic()
    row = {"model": client.model_id, "condition": condition, "at": datetime.now(timezone.utc).isoformat()}
    try:
        reply = client.converse(
            system=prompts.system_text(condition),
            messages=[{"role": "user", "content": [{"text": prompts.opening}]}],
            tool_config=prompts.tool_config, inference=INFERENCE_CONFIG)
    except ModelError as err:
        # An error is neither a block nor a pass. It is counted on its own and never in either denominator.
        return {**row, "stop_reason": None, "error_kind": err.kind, "retries": err.retries,
                "latency_s": round(time.monotonic() - began, 3)}
    return {**row, "stop_reason": reply.stop_reason, "first_block": first_block_kind(reply.content),
            "input_tokens": reply.input_tokens, "output_tokens": reply.output_tokens,
            "request_id": reply.request_id, "retries": reply.retries, "error_kind": None,
            "latency_s": round(time.monotonic() - began, 3)}


def run_probe(clients: dict[str, ModelClient], prompts: Prompts, n: int, sink: Callable[[dict], None],
              conditions: tuple[str, ...] = CONDITIONS) -> list[dict]:
    """N rounds; in each round every (model, condition) cell gets one call, conditions alternating, so the
    cells are sampled across the same stretch of time."""
    rows: list[dict] = []
    consecutive_errors = 0
    for round_number in range(1, n + 1):
        for key, client in clients.items():
            for condition in conditions:
                row = {**probe_once(client, prompts, condition), "round": round_number, "model_key": key}
                rows.append(row)
                sink(row)
                consecutive_errors = consecutive_errors + 1 if row["error_kind"] else 0
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                    raise RuntimeError(f"{MAX_CONSECUTIVE_ERRORS} calls in a row failed ({row['error_kind']}): stopping")
    return rows


def summarize(rows: list[dict]) -> list[dict]:
    """One line per (model, condition): the blocked rate among calls that got an answer, with its interval."""
    cells: dict[tuple[str, str], list[dict]] = {}
    for row in rows:
        cells.setdefault((row["model_key"], row["condition"]), []).append(row)
    summary = []
    for (key, condition), group in cells.items():
        answered = [r for r in group if not r["error_kind"]]
        blocked = sum(r["stop_reason"] == BLOCKED for r in answered)
        low, high = wilson(blocked, len(answered))
        tin = sum(r.get("input_tokens", 0) for r in answered)
        tout = sum(r.get("output_tokens", 0) for r in answered)
        price_in, price_out = PRICES[key]
        summary.append({
            "model": key, "condition": condition, "calls": len(group), "errors": len(group) - len(answered),
            "answered": len(answered), "blocked": blocked, "blocked_rate": blocked / len(answered) if answered else None,
            "ci_low": low, "ci_high": high,
            "other_stops": dict(Counter(r["stop_reason"] for r in answered if r["stop_reason"] != BLOCKED)),
            "input_tokens": tin, "output_tokens": tout,
            "estimated_cost_usd": tin * price_in / 1e6 + tout * price_out / 1e6,
        })
    return summary


def format_summary(summary: list[dict]) -> str:
    lines = [f"{'model':<6} {'condition':<8} {'answered':>8} {'blocked':>8} {'rate':>6}  {'95% Wilson':<11} {'errors':>6}  other stop reasons"]
    for s in summary:
        rate = "n/a" if s["blocked_rate"] is None else f"{s['blocked_rate']:.0%}"
        lines.append(f"{s['model']:<6} {s['condition']:<8} {s['answered']:>8} {s['blocked']:>8} {rate:>6}  "
                     f"{s['ci_low']:.0%}-{s['ci_high']:.0%}".ljust(11) + f"  {s['errors']:>6}  {s['other_stops'] or '-'}")
    total = sum(s["estimated_cost_usd"] for s in summary)
    lines.append(f"\nestimated cost of these calls: ${total:.4f} (token counts x the PRICES table; unverified against the bill)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--n", type=int, default=30, help="calls per (model, condition) cell")
    parser.add_argument("--models", default="micro", help="comma-separated: micro, pro (default micro, the evaluated model, D-023)")
    parser.add_argument("--out", type=Path, default=None, help="JSONL path (default runs/filter_probe/<timestamp>.jsonl)")
    args = parser.parse_args(argv)
    keys = [k.strip() for k in args.models.split(",") if k.strip()]
    unknown = [k for k in keys if k not in MODEL_KEYS]
    if not keys or unknown or args.n < 1:
        parser.error(f"need at least one model from {sorted(MODEL_KEYS)} (got {keys}, unknown: {unknown}) and n >= 1")

    out = args.out or ROOT / "runs" / "filter_probe" / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)
    clients = {key: bedrock_from_env(MODEL_KEYS[key]) for key in keys}
    print(f"{args.n} calls per cell x {len(keys) * len(CONDITIONS)} cells = {args.n * len(keys) * len(CONDITIONS)} calls; rows go to {out}")
    with open(out, "a", encoding="utf-8", newline="\n") as handle:
        def sink(row: dict) -> None:
            handle.write(json.dumps(row) + "\n")
            handle.flush()
            if row["round"] % 5 == 0 and row["condition"] == CONDITIONS[-1] and row["model_key"] == keys[-1]:
                print(f"  round {row['round']}/{args.n} done", flush=True)

        rows = run_probe(clients, load_prompts(), args.n, sink)
    print("\n" + format_summary(summarize(rows)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
