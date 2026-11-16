"""Fill a committed skeleton's placeholders from one of your real hand-exploit runs (D-035,
D-039, D-044). A local tool; its OUTPUT (the filled runs) is gitignored, never committed.

What this script fills and why that's the whole scope: looking at build.py, only these
kinds of field hold literal `<FILL: ...>` content tied to a real request:
    - an injectable-path event's `params[<param>]`, `input_used`, `executed_sql`, and
      (on a bound/parameterized variant only) `sql_params` -- render_bound puts the
      same placeholder inside it
    - a login event's `params` (the submitted form fields)
Everything else build.py marks as a placeholder -- a step's `tool_input.command`,
`output_full`/`output_sent_to_model`, and every step's `assistant_text` -- has NO source
in a hand-exploit run. hand_lab.py never records what you typed in the attacker shell or
its raw output, only what the TARGET logged server-side; and `assistant_text` is a model's
own reasoning, which a human standing in for the agent doesn't produce. This script fills
what it safely can and REPORTS the rest, by file and field, rather than leaving silent gaps.

Usage:
    .venv/Scripts/python tests/fixtures/skeletons/fill_locally.py list
    .venv/Scripts/python tests/fixtures/skeletons/fill_locally.py gaps genuine_full
    .venv/Scripts/python tests/fixtures/skeletons/fill_locally.py apply genuine_full \\
        --run ../../../runs/hand/B/target-events-20261115T225533Z.jsonl \\
        --map 2=5 3=9 4=12 5=14

`--map <skeleton event position>=<real event seq>` tells the script which of your real
logged events plays which role in the skeleton. Run `gaps` first: it lists each skeleton
event's position alongside its method/path/sql_error/creds/login fields, so you can match
it to the right real seq by eye. The mapping is yours to decide -- the script never guesses
which of several real requests was "the" probe or "the" extraction.

`gaps` always reads the COMMITTED skeleton by default -- it never looks at a filled copy,
since the committed one is never modified (D-039). To check what's left in what you've
already filled, point it at that copy instead:
    .venv/Scripts/python tests/fixtures/skeletons/fill_locally.py gaps genuine_full \\
        --path tests/fixtures/skeletons_filled/genuine_full

`gaps --all` reports every committed skeleton at once, instead of needing a name -- an
overview of what the whole set still needs. `--targets`/`--steps` narrow either form to
just the target_events.jsonl gaps (what `apply --map` could still close) or just the
steps.jsonl ones (what has no source and must be authored directly):
    .venv/Scripts/python tests/fixtures/skeletons/fill_locally.py gaps --all --targets
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SKEL = Path(__file__).resolve().parent
OUT_ROOT = ROOT / "tests" / "fixtures" / "skeletons_filled"
sys.path.insert(0, str(ROOT / "harness"))
sys.path.insert(0, str(ROOT / "target"))

from target_logs import collect_events  # noqa: E402
from telemetry import _check_sql, validate_record  # noqa: E402

FILES = ["manifest.json", "steps.jsonl", "target_events.jsonl", "intent.json", "score.json"]


def list_skeletons() -> list[str]:
    return sorted(p.name for p in SKEL.iterdir() if p.is_dir() and (p / "manifest.json").exists())


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8", newline="\n")


def load_skeleton(skel_dir: Path) -> dict:
    """{"manifest": dict, "steps": list[dict], "events": list[dict], "intent": dict,
    "score": dict | None}. Raises FileNotFoundError on a bad directory."""
    rec = {
        "manifest": json.loads((skel_dir / "manifest.json").read_text(encoding="utf-8")),
        "steps": _read_jsonl(skel_dir / "steps.jsonl"),
        "events": _read_jsonl(skel_dir / "target_events.jsonl"),
        "intent": json.loads((skel_dir / "intent.json").read_text(encoding="utf-8")),
    }
    score_path = skel_dir / "score.json"
    rec["score"] = json.loads(score_path.read_text(encoding="utf-8")) if score_path.exists() else None
    return rec


def write_skeleton(out_dir: Path, rec: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "manifest.json").write_text(json.dumps(rec["manifest"], indent=2), encoding="utf-8", newline="\n")
    _write_jsonl(out_dir / "steps.jsonl", rec["steps"])
    _write_jsonl(out_dir / "target_events.jsonl", rec["events"])
    (out_dir / "intent.json").write_text(json.dumps(rec["intent"], indent=2), encoding="utf-8", newline="\n")
    if rec["score"] is not None:
        (out_dir / "score.json").write_text(json.dumps(rec["score"], indent=2), encoding="utf-8", newline="\n")


def find_fills(obj, prefix: str = "") -> list[tuple[str, str]]:
    """Every `<FILL: ...>` string still present, as (dotted/indexed path, its text)."""
    found: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            found += find_fills(value, f"{prefix}.{key}" if prefix else key)
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            found += find_fills(value, f"{prefix}[{index}]")
    elif isinstance(obj, str) and obj.startswith("<FILL:"):
        found.append((prefix, obj))
    return found


def _event_position(path: str) -> int | None:
    """"[2].params.ref" -> 3 (1-based, matching the --map / the skeleton's own seq)."""
    if not path.startswith("["):
        return None
    return int(path[1:path.index("]")]) + 1


def describe_gaps(rec: dict, sections: set[str] | None = None) -> list[str]:
    """Human-readable lines: what's still a placeholder, grouped by file, with why.

    `sections`, when given, restricts this to a subset of {"manifest", "steps",
    "events", "intent", "score"} -- e.g. {"events"} for --targets, {"steps"} for
    --steps. None (the default) shows everything, same as before either flag existed.
    """
    lines: list[str] = []
    fillable_positions: set[int] = set()

    for file_key, filename, container in (
        ("manifest", "manifest.json", rec["manifest"]),
        ("steps", "steps.jsonl", rec["steps"]),
        ("events", "target_events.jsonl", rec["events"]),
        ("intent", "intent.json", rec["intent"]),
        ("score", "score.json", rec["score"]),
    ):
        if sections is not None and file_key not in sections:
            continue
        fills = find_fills(container)
        if not fills:
            continue
        lines.append(f"{filename}:")
        for path, _ in fills:
            if file_key == "steps" and path.endswith(".assistant_text"):
                note = "no source: the agent's own reasoning -- not attack content, write it directly"
            elif file_key == "steps":
                note = "no source: hand_lab never records your typed commands or their raw output"
            elif file_key == "events":
                position = _event_position(path)
                if position is not None:
                    fillable_positions.add(position)
                note = (f"fillable: apply --map {position}=<real seq>" if position is not None
                        else "fillable, but this script can't locate its event position")
            else:
                note = "no source: author this directly, it isn't attack content"
            lines.append(f"  {path}  ({note})")

    if fillable_positions:
        lines.append("")
        lines.append(f"event positions apply can fill: {sorted(fillable_positions)}")
    return lines


def apply_fill(rec: dict, real_by_seq: dict[int, dict], mapping: dict[int, int]) -> list[str]:
    """Mutates rec["events"] in place. Returns human-readable notes, including any
    structural mismatch between a skeleton event's assumed shape and the real one."""
    cfg = rec["manifest"]["variant_config"]
    events = rec["events"]
    notes: list[str] = []

    for position, real_seq in sorted(mapping.items()):
        if not 1 <= position <= len(events):
            raise ValueError(f"event position {position} is out of range (this skeleton has {len(events)} events)")
        if real_seq not in real_by_seq:
            raise ValueError(f"no event with seq {real_seq} in the real run")
        skel_event, real_event = events[position - 1], real_by_seq[real_seq]

        if skel_event["path"] == cfg["injectable_path"]:
            skel_event["input_used"] = real_event["input_used"]
            skel_event["executed_sql"] = real_event["executed_sql"]
            skel_event["params"] = dict(real_event["params"])
            # On a bound (parameterized) variant, render_bound puts the input inside
            # sql_params too -- a placeholder there is as real as one in input_used.
            # Harmless to copy on an unbound variant: real_event["sql_params"] is [].
            skel_event["sql_params"] = list(real_event["sql_params"])
            notes.append(f"event {position} (search, real seq {real_seq}): "
                         f"input_used, executed_sql, params, sql_params filled")
        elif skel_event["path"] == cfg["login_path"]:
            if set(skel_event["params"]) != set(real_event["params"]):
                notes.append(f"event {position} (login): params shape changed from "
                             f"{sorted(skel_event['params'])} to the real shape {sorted(real_event['params'])} "
                             f"-- the skeleton's placeholder shape was wrong; consider fixing build.py too")
            skel_event["params"] = dict(real_event["params"])
            notes.append(f"event {position} (login, real seq {real_seq}): params filled")
        else:
            raise ValueError(f"event {position} is on {skel_event['path']!r}, neither the injectable nor the "
                             f"login path ({cfg['injectable_path']!r} / {cfg['login_path']!r}) -- nothing to copy")
    return notes


def validate_filled(rec: dict) -> list[str]:
    """The same checks hand_lab's `check` runs: schema plus the manifest/event SQL cross-check."""
    problems = []
    for index, event in enumerate(rec["events"], start=1):
        problems += [f"event {index}: {p}" for p in validate_record("target_event", event)]
    problems += _check_sql(rec["manifest"], rec["events"])
    return problems


# --- CLI -----------------------------------------------------------------------------

def cmd_list() -> None:
    for name in list_skeletons():
        print(name)


def _print_gaps(label: str, rec: dict, sections: set[str] | None) -> None:
    lines = describe_gaps(rec, sections)
    print(f"{label}:\n" + ("\n".join(lines) if lines else "  nothing left -- every placeholder is filled"))


def cmd_gaps(name: str | None, path: Path | None, *, show_all: bool = False,
            sections: set[str] | None = None) -> None:
    """Defaults to the committed (always-placeholder) skeleton. --path points it at a
    filled copy instead -- e.g. tests/fixtures/skeletons_filled/<name> -- since gaps
    never reads that location on its own (the committed skeleton is never modified).
    --all ignores name/path and reports every committed skeleton, one after another --
    an overview of what the whole set still needs, not just one. `sections` narrows
    either case to just {"events"} (--targets) or {"steps"} (--steps)."""
    if show_all:
        if name is not None or path is not None:
            raise SystemExit("--all can't be combined with a skeleton name or --path")
        for index, skeleton_name in enumerate(list_skeletons()):
            if index:
                print()
            _print_gaps(skeleton_name, load_skeleton(SKEL / skeleton_name), sections)
        return

    if path is not None:
        skel_dir, label = path, str(path)
    elif name is not None:
        if name not in list_skeletons():
            raise SystemExit(f"no such committed skeleton: {name!r} (see `list`)")
        skel_dir, label = SKEL / name, name
    else:
        raise SystemExit("gaps needs a skeleton name, --path, or --all")

    _print_gaps(label, load_skeleton(skel_dir), sections)


def cmd_apply(name: str, run_path: Path, mapping: dict[int, int]) -> None:
    rec = load_skeleton(SKEL / name)
    real_events = collect_events(run_path.read_text(encoding="utf-8"), "0" * 32)
    real_by_seq = {e["seq"]: e for e in real_events}

    notes = apply_fill(rec, real_by_seq, mapping)
    out_dir = OUT_ROOT / name
    write_skeleton(out_dir, rec)

    print(f"wrote {out_dir.relative_to(ROOT)}\n")
    for note in notes:
        print(" -", note)

    problems = validate_filled(rec)
    print("\nschema and SQL cross-check:", "no problems" if not problems else "")
    for problem in problems:
        print("  -", problem)

    print()
    gap_lines = describe_gaps(rec)
    print("still needs filling:" if gap_lines else "nothing left unfilled")
    for line in gap_lines:
        print(" ", line)


def _parse_mapping(pairs: list[str]) -> dict[int, int]:
    mapping = {}
    for pair in pairs:
        key, _, value = pair.partition("=")
        if not value:
            raise SystemExit(f"--map entries must look like 2=5, not {pair!r}")
        mapping[int(key)] = int(value)
    return mapping


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    gaps = sub.add_parser("gaps")
    gaps.add_argument("name", nargs="?", help="a committed skeleton name (reads tests/fixtures/skeletons/<name>)")
    gaps.add_argument("--path", type=Path,
                      help="inspect this directory instead, e.g. tests/fixtures/skeletons_filled/<name>")
    gaps.add_argument("--all", action="store_true",
                      help="report every committed skeleton, one after another, instead of just one")
    section = gaps.add_mutually_exclusive_group()
    section.add_argument("--targets", action="store_true", help="show only target_events.jsonl gaps")
    section.add_argument("--steps", action="store_true", help="show only steps.jsonl gaps")
    apply_p = sub.add_parser("apply")
    apply_p.add_argument("name", choices=list_skeletons())
    apply_p.add_argument("--run", required=True, type=Path, help="a saved runs/hand/<variant>/target-events-*.jsonl")
    apply_p.add_argument("--map", nargs="+", required=True, metavar="POS=SEQ",
                         help="skeleton event position = real event seq, e.g. 2=5 3=9")
    args = parser.parse_args(argv)

    if args.command == "list":
        cmd_list()
    elif args.command == "gaps":
        sections = {"events"} if args.targets else {"steps"} if args.steps else None
        cmd_gaps(args.name, args.path, show_all=args.all, sections=sections)
    elif args.command == "apply":
        cmd_apply(args.name, args.run, _parse_mapping(args.map))


if __name__ == "__main__":
    main()
