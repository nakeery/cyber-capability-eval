"""The pilot's tally (PLAN.md phase 5): what the pilot shakeout's runs say about the pipeline, per cell.

The pilot is a shakeout, not a floor test (3 runs per cell; 0 of 3 is still compatible with a rate near 56%), so this
prints COUNTS, never a rate comparison. It answers the phase 5 bullets that need run data:

  * the outcome of each run, through `outcome()` (D-074, D-097) and never from `score.json` alone: how many runs
    count (scored or fail), how many were replaced and why, and how many are unscored (D-097's "unscored");
  * how often `context_limit` fires (D-062);
  * how many runs end text-only after at least one command (D-075: the primary count, the attempts-included count
    beside it), how many reach the nudge limit (D-083, D-084), and nudges per run;
  * the malformed-turn rate and its causes, how many `invalid_arguments` turns strictness alone causes (a harmless
    extra key), and replies cut off at `max_tokens` (the temperature check, D-084).

Every step is read through `step_kind` (D-075), so a full-window or platform-block step is never counted as the
model's own text-only turn. Runs that do not validate are tallied but flagged, never silently included or dropped.
A difference in the replaced count between the two conditions of one variant is printed as a finding to investigate
(D-074's caveat: replacement is unbiased only if infrastructure failures are independent of the arm).

Selection is explicit, never silent: `--commit`, `--since` and `--order-seed` narrow the runs directory, and the
count of directories that matched nothing is printed. Baseline directories (baseline_result.json) are skipped.

Usage:
    .venv/Scripts/python harness/pilot_tally.py [--runs-dir DIR] [--commit HASH] [--since ISO] [--order-seed N]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "harness"))
sys.path.insert(0, str(ROOT / "target"))

import telemetry  # noqa: E402
from agent import TOOL_ARGUMENT  # noqa: E402
from outcome import FAIL, REPLACED, SCORED, UNSCORED, load_outcome  # noqa: E402
from step_kind import ends_text_only_after_a_command, hit_the_nudge_limit, step_kind  # noqa: E402

RUNS_DIR = ROOT / "runs"
PILOT_PER_CELL = 3                 # PLAN.md phase 5: "3 runs per cell"
UNCLASSIFIED = "unclassified"      # a termination_reason the outcome table does not know (outcome() raised)


# --- one run -------------------------------------------------------------------------------------


def strictness_only(step: dict) -> bool:
    """True for an `invalid_arguments` turn that holds exactly one well-named call whose required argument is present
    and a string, and that is invalid only because it ALSO carries extra keys: D-063's "harmless extra key". Read
    from the recorded raw call; anything it cannot read is not claimed to be strictness."""
    if step.get("tool_call_error") != "invalid_arguments":
        return False
    blocks = step.get("raw_tool_use") or []
    if len(blocks) != 1 or not isinstance(blocks[0], dict):
        return False
    call = blocks[0].get("toolUse") or blocks[0]
    arguments = call.get("input") if isinstance(call, dict) else None
    key = TOOL_ARGUMENT.get(call.get("name")) if isinstance(call, dict) else None
    return (key is not None and isinstance(arguments, dict) and isinstance(arguments.get(key), str)
            and set(arguments) != {key})


def step_facts(steps: list[dict], termination: str) -> dict:
    """Counts over one run's recorded steps. Pure."""
    kinds = Counter(step_kind(step) for step in steps)
    causes = Counter(step["tool_call_error"] for step in steps if step.get("tool_call_error"))
    return {
        "steps": len(steps),
        "kinds": dict(kinds),
        "malformed": kinds["malformed"],
        "malformed_causes": dict(causes),
        "strictness_only": sum(1 for step in steps if strictness_only(step)),
        "max_tokens_cuts": sum(1 for step in steps if step.get("stop_reason") == "max_tokens"),
        "nudges": sum(1 for step in steps if step.get("nudged")),
        "text_only_after_command": ends_text_only_after_a_command(steps, termination),
        "text_only_after_attempt": ends_text_only_after_a_command(steps, termination, attempts=True),
        "hit_nudge_limit": hit_the_nudge_limit(steps, termination),
    }


def read_run(run_dir: Path) -> dict | None:
    """The facts of one run directory, or None when it is not a model run at all (a baseline directory, or one with
    neither a manifest nor a partial manifest). Never raises for a damaged run: the damage is a fact."""
    run_dir = Path(run_dir)
    if (run_dir / "baseline_result.json").exists():
        return None
    manifest_path = run_dir / "manifest.json"
    finished = manifest_path.exists()
    try:
        record = json.loads((manifest_path if finished else run_dir / "manifest.partial.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(record, dict) or "variant" not in record:
        return None
    facts = {
        "run_id": record.get("run_id", run_dir.name), "variant": record["variant"], "condition": record.get("condition"),
        "commit": record.get("harness_commit"), "order_seed": record.get("run_order_seed"),
        "started_at": record.get("started_at") if finished else record.get("begun_at"),
        "finished": finished, "termination": record.get("termination_reason"), "problems": [], "dirty": [],
        "_dir": str(run_dir),      # the directory actually read, never assumed from run_id (it need not match it)
    }
    if not finished:
        verdict = load_outcome(run_dir)
        facts.update(outcome=verdict.kind, passed=verdict.passed, outcome_reason=verdict.reason, steps=None)
        return facts
    notes = _read_json(run_dir / "harness_notes.json") or {}
    facts["dirty"] = list(notes.get("dirty_paths") or [])
    try:
        verdict = load_outcome(run_dir)
        facts.update(outcome=verdict.kind, passed=verdict.passed, outcome_reason=verdict.reason)
    except ValueError as err:
        facts.update(outcome=UNCLASSIFIED, passed=None, outcome_reason=str(err))
    score = _read_json(run_dir / "score.json") or {}
    facts["milestones"] = list(score.get("milestones") or []) if verdict_counts(facts["outcome"]) else []
    try:
        facts["problems"] = telemetry.validate_run_dir(run_dir, include_score=False)
        steps = telemetry.load_run(run_dir)[1]
        facts.update(step_facts(steps, facts["termination"]))
    except (OSError, ValueError) as err:
        facts["problems"] = facts["problems"] or [f"unreadable: {err}"]
        facts["steps"] = None
    return facts


def verdict_counts(kind: str) -> bool:
    """A run whose outcome counts toward its cell's N (scored or fail): replaced and unscored runs do not."""
    return kind in (SCORED, FAIL)


def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


# --- selecting runs ------------------------------------------------------------------------------


def selected(facts: dict, *, commit: str | None, since: datetime | None, order_seed: int | None) -> bool:
    """Whether a run is in the pilot. A run that never finished is matched by seed too, because the partial manifest
    records `run_order_seed` from the start. A partial manifest from before that was recorded has no seed, so it is NOT
    matched by `--order-seed` (it cannot be shown to belong to the batch); `--since` still selects it."""
    if commit is not None and not str(facts["commit"] or "").startswith(commit):
        return False
    if since is not None:
        try:
            if datetime.fromisoformat(facts["started_at"]) < since:
                return False
        except (TypeError, ValueError):
            return False
    if order_seed is not None and facts["order_seed"] != order_seed:
        return False
    return True


def load_pilot(runs_dir: Path, *, commit: str | None = None, since: datetime | None = None,
               order_seed: int | None = None) -> tuple[list[dict], int]:
    """(the selected runs, the number of run directories that were not selected). Oldest first."""
    chosen, skipped = [], 0
    for run_dir in sorted(Path(runs_dir).iterdir()) if Path(runs_dir).is_dir() else []:
        if not run_dir.is_dir():
            continue
        facts = read_run(run_dir)
        if facts is None or not selected(facts, commit=commit, since=since, order_seed=order_seed):
            skipped += 1
            continue
        chosen.append(facts)
    chosen.sort(key=lambda f: str(f["started_at"]))
    return chosen, skipped


# --- one cell, and the cells ---------------------------------------------------------------------


def tally_cell(runs: list[dict]) -> dict:
    """Counts for one (variant, condition) cell. Pure over `read_run`'s facts."""
    counted = [r for r in runs if verdict_counts(r["outcome"])]
    replaced = [r for r in runs if r["outcome"] == REPLACED]
    measured = [r for r in runs if r.get("steps") is not None]      # a run with readable steps
    total_steps = sum(r["steps"] for r in measured)
    cell = {
        "dirs": len(runs),
        "counted": len(counted), "passed": sum(1 for r in counted if r["passed"]),
        "failed_by_cause": sum(1 for r in runs if r["outcome"] == FAIL),
        "replaced": len(replaced), "replaced_reasons": Counter(r["outcome_reason"] for r in replaced),
        "unscored": sum(1 for r in runs if r["outcome"] == UNSCORED),
        "unclassified": sum(1 for r in runs if r["outcome"] == UNCLASSIFIED),
        "termination": Counter(r["termination"] for r in runs),
        "context_limit_runs": sum(1 for r in runs if r["termination"] == "context_limit"),
        "milestones": Counter(m for r in counted for m in r.get("milestones", [])),
        "not_valid": [r["run_id"][:8] for r in runs if r["problems"]],
        "development": [r["run_id"][:8] for r in runs if r["dirty"]],
        "measured_runs": len(measured), "steps": total_steps,
        "malformed": sum(r["malformed"] for r in measured),
        "malformed_causes": sum((Counter(r["malformed_causes"]) for r in measured), Counter()),
        "strictness_only": sum(r["strictness_only"] for r in measured),
        "max_tokens_cuts": sum(r["max_tokens_cuts"] for r in measured),
        "nudges": sum(r["nudges"] for r in measured),
        "text_only_after_command": sum(1 for r in measured if r["text_only_after_command"]),
        "text_only_after_attempt": sum(1 for r in measured if r["text_only_after_attempt"]),
        "hit_nudge_limit": sum(1 for r in measured if r["hit_nudge_limit"]),
        "short_by": max(0, PILOT_PER_CELL - len(counted)),
    }
    return cell


def tally(runs: list[dict]) -> dict[tuple[str, str], dict]:
    cells: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for run in runs:
        cells[(run["variant"], run["condition"])].append(run)
    return {key: tally_cell(cell) for key, cell in sorted(cells.items(), key=lambda kv: (kv[0][0], str(kv[0][1])))}


def _ids(ids: list[str], shown: int = 5) -> str:
    """Run ids for a finding line: the first few, then how many more (a cell of development runs can hold hundreds)."""
    return ", ".join(ids[:shown]) + (f" and {len(ids) - shown} more" if len(ids) > shown else "")


def findings(cells: dict[tuple[str, str], dict]) -> list[str]:
    """What the counts ask to be looked at (never averaged away)."""
    out = []
    for (variant, condition), c in cells.items():
        if c["short_by"]:
            out.append(f"{variant} {condition}: {c['counted']} counted run(s), the pilot asks for {PILOT_PER_CELL} "
                       f"({c['short_by']} short: replaced runs are drawn again, D-074)")
        if c["unclassified"]:
            out.append(f"{variant} {condition}: {c['unclassified']} run(s) with an ending the outcome table does not know")
        if c["not_valid"]:
            out.append(f"{variant} {condition}: run(s) {_ids(c['not_valid'])} do not validate (the scorer refuses them, D-057)")
        if c["development"]:
            out.append(f"{variant} {condition}: run(s) {_ids(c['development'])} were made with uncommitted changes "
                       f"(development runs, not study data)")
    by_variant: dict[str, dict[str, int]] = defaultdict(dict)
    for (variant, condition), c in cells.items():
        by_variant[variant][condition] = c["replaced"]
    for variant, counts in sorted(by_variant.items()):
        if len(set(counts.values())) > 1 and len(counts) > 1:
            out.append(f"{variant}: replaced runs differ between conditions {counts}: investigate before absorbing "
                       f"(D-074's caveat: replacement assumes failures independent of the arm)")
    return out


# --- rendering -----------------------------------------------------------------------------------


def _ratio(k: int, n: int) -> str:
    return f"{k}/{n}"


def render(cells: dict[tuple[str, str], dict], skipped: int, notes: list[str]) -> str:
    lines = [f"Pilot tally. COUNTS only (a pilot is a shakeout, not a floor test, PLAN.md phase 5). "
             f"{skipped} run director{'y' if skipped == 1 else 'ies'} not selected.", ""]
    head = (f"{'variant':<8}{'condition':<10}{'dirs':>5}{'counted':>9}{'pass':>6}{'fail*':>6}{'repl':>6}{'unsc':>6}"
            f"{'ctx_lim':>9}{'steps':>7}{'malf':>6}{'strict':>7}{'maxtok':>7}{'nudges':>8}{'txt>cmd':>9}{'(+att)':>7}{'nudgeLim':>9}")
    lines += [head, "-" * len(head)]
    for (variant, condition), c in cells.items():
        lines.append(f"{variant:<8}{str(condition):<10}{c['dirs']:>5}{c['counted']:>9}{c['passed']:>6}{c['failed_by_cause']:>6}"
                     f"{c['replaced']:>6}{c['unscored']:>6}{c['context_limit_runs']:>9}{c['steps']:>7}{c['malformed']:>6}"
                     f"{c['strictness_only']:>7}{c['max_tokens_cuts']:>7}{c['nudges']:>8}{c['text_only_after_command']:>9}"
                     f"{c['text_only_after_attempt']:>7}{c['hit_nudge_limit']:>9}")
    lines += ["",
              "counted = scored + fail (outcome(), D-074); pass = counted runs the scorer passed; fail* = agent-caused failures",
              "(a subset of counted); repl = replaced; unsc = unscored; ctx_lim = runs that ended as context_limit;",
              "malf = malformed turns; strict = invalid_arguments turns caused only by extra keys; maxtok = replies cut at",
              "max_tokens; txt>cmd = runs ending text-only after a command, (+att) also counting an earlier malformed call;",
              "nudgeLim = runs that reached the nudge limit."]
    lines += ["", "Per cell:"]
    for (variant, condition), c in cells.items():
        runs, steps = c["measured_runs"], c["steps"]
        rate = f"{c['malformed']}/{steps} = {c['malformed'] / steps:.1%}" if steps else "no steps"
        per_run = f"{c['nudges'] / runs:.2f}" if runs else "n/a"
        causes = ", ".join(f"{k} {v}" for k, v in sorted(c["malformed_causes"].items())) or "none"
        reasons = "; ".join(f"{reason} x{n}" for reason, n in c["replaced_reasons"].items()) or "none"
        ends = ", ".join(f"{k} {v}" for k, v in sorted(c["termination"].items(), key=lambda kv: str(kv[0])))
        marks = ", ".join(f"{k} {v}" for k, v in sorted(c["milestones"].items())) or "none"
        lines += [f"  {variant} {condition}: ended: {ends}",
                  f"    malformed rate {rate} (causes: {causes}); nudges per run {per_run}",
                  f"    replaced: {reasons}",
                  f"    scorer milestones among counted runs: {marks}"]
    lines += ["", "Findings: " + ("none." if not notes else "")] + [f"  - {n}" for n in notes]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runs-dir", type=Path, default=RUNS_DIR)
    parser.add_argument("--commit", help="keep only runs made at this harness commit (a prefix)")
    parser.add_argument("--since", help="keep only runs started at or after this ISO time (with a UTC offset)")
    parser.add_argument("--order-seed", type=int, help="keep only runs with this run_order_seed, finished or not (pilot.ps1 draws one at random and prints it)")
    args = parser.parse_args(argv)
    since = None
    if args.since:
        try:
            since = datetime.fromisoformat(args.since)
        except ValueError:
            print(f"--since is not an ISO time: {args.since!r}")
            return 2
        if since.tzinfo is None:
            print("--since needs a UTC offset, for example 2026-11-20T09:00:00+00:00 (run times are timezone-aware)")
            return 2
    runs, skipped = load_pilot(args.runs_dir, commit=args.commit, since=since, order_seed=args.order_seed)
    cells = tally(runs)
    print(render(cells, skipped, findings(cells)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
