"""The hand-labeling sheet for labeler validation (PLAN.md phase 5): make it, then check what you filled in.

    .venv/Scripts/python labeling/sheet.py make --latest 24            # the 24 newest model runs, shuffled
    .venv/Scripts/python labeling/sheet.py make --order-seed 16009     # one pilot's own batch (D-098), not by recency
    .venv/Scripts/python labeling/sheet.py make runs/<id> runs/<id>    # or name the run directories
    .venv/Scripts/python labeling/sheet.py check runs/labeling/sheet.csv

`make` writes a CSV with one row per run and the run's id only: no variant, condition or score, so
the row itself does not prime you. (You will still open the manifest to read the flag and
password, and the score to decide `scorer_agreement`: label the outcome first, from the steps and target
events, and look at the score last.) Rows are shuffled with a recorded seed so run order does not tell you
the cell either. Fill in the blank columns by hand; the vocabulary and the rules are in labeling/GUIDE.md.

`check` turns every filled-in row into a label record and validates it with the real label schema
(`schemas/label.schema.json`), so a misspelled label, a `GENUINE_PARTIAL` without a `highest_milestone`,
or a `NO_PROGRESS` without a `detail` is caught here, not at comparison time. It also refuses an evidence
cell that contains the run's flag or admin password (the schema's own rule: evidence never holds them).
A blank row is reported as unlabeled, not as an error.

Your sheet is a working file: it goes under `runs/` (gitignored) by default and is never committed.
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "harness"))

import pilot_tally  # noqa: E402  (D-098's reader: resolves --order-seed to a batch's run directories)
import telemetry  # noqa: E402

RUNS_DIR = ROOT / "runs"
DEFAULT_OUT = RUNS_DIR / "labeling" / "sheet.csv"
COLUMNS = ("run_id", "outcome_label", "highest_milestone", "detail", "tags", "scorer_agreement",
           "key_evidence", "definition_notes")
LABEL_COLUMNS = ("outcome_label", "highest_milestone", "detail", "tags", "scorer_agreement", "key_evidence")
TAG_SEPARATOR = ";"


def load_manifest(run_dir: Path) -> dict | None:
    """The run's manifest, or None if the directory is not a model run (a baseline run has no manifest)."""
    path = Path(run_dir) / "manifest.json"
    if not path.exists():
        return None
    return telemetry._read_json(path)


def pick_runs(run_dirs: list[Path], latest: int | None, runs_dir: Path, order_seed: int | None = None) -> list[Path]:
    """The directories to label: those named, the finished runs of a batch (`order_seed`, D-098 -- the
    same batch `pilot_tally --order-seed` and `compare.py --model-run-seed` would read), or the `latest`
    newest model runs by manifest `started_at`. `--latest` picks by recency, which silently mixes batches
    if anything else (a stray test run, a second pilot) was made since; `--order-seed` picks by the batch
    the runs actually recorded themselves under, so prefer it once a run has one."""
    if run_dirs:
        missing = [str(d) for d in run_dirs if load_manifest(d) is None]
        if missing:
            raise ValueError(f"not a model run (no manifest.json): {missing}")
        return list(run_dirs)
    if order_seed is not None:
        if latest is not None:
            raise ValueError("pass --latest or --order-seed, not both")
        facts, _skipped, _damaged = pilot_tally.load_pilot(runs_dir, order_seed=order_seed)
        return [Path(f["_dir"]) for f in facts if f["finished"]]
    if latest is None:
        raise ValueError("name run directories, pass --latest N, or pass --order-seed N")
    found = []
    for path in sorted(Path(runs_dir).iterdir()):
        manifest = load_manifest(path) if path.is_dir() else None
        if manifest is not None:
            found.append((manifest["started_at"], path))
    found.sort()
    return [path for _, path in found[-latest:]]


def make_sheet(run_dirs: list[Path], out: Path, seed: int) -> list[str]:
    """Write the blank sheet (shuffled by `seed`); returns the run ids in sheet order."""
    ids = [load_manifest(d)["run_id"] for d in run_dirs]
    random.Random(seed).shuffle(ids)
    out = Path(out)
    if out.exists():
        raise ValueError(f"{out} already exists: it may hold your labels, so it is never overwritten")
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        for run_id in ids:
            writer.writerow({"run_id": run_id})
    return ids


def row_to_record(row: dict[str, str]) -> dict:
    """One filled-in row as a label record (the schema's shape). Empty optional cells are left out."""
    record: dict = {"schema_version": "1", "run_id": row["run_id"].strip()}
    for field in ("outcome_label", "scorer_agreement"):
        record[field] = row[field].strip()
    record["tags"] = [t.strip() for t in row["tags"].split(TAG_SEPARATOR) if t.strip()]
    for field in ("highest_milestone", "detail"):
        if row[field].strip():
            record[field] = row[field].strip()
    record["evidence"] = row["key_evidence"].strip()
    return record


def is_blank(row: dict[str, str]) -> bool:
    return not any(row[c].strip() for c in LABEL_COLUMNS)


def check_sheet(path: Path, runs_dir: Path = RUNS_DIR) -> tuple[list[str], dict[str, int]]:
    """(problems, counts). counts has labeled, unlabeled and notes (rows with a definition note)."""
    problems: list[str] = []
    counts = {"labeled": 0, "unlabeled": 0, "notes": 0}
    # Indexed by the manifest's own run_id, never assumed from the directory name: a directory can be
    # renamed, restaged or archived without the run_id inside it changing (baseline/compare.py's own rule).
    by_run_id: dict[str, dict] = {}
    for run_dir in Path(runs_dir).iterdir() if Path(runs_dir).exists() else []:
        manifest = load_manifest(run_dir) if run_dir.is_dir() else None
        if manifest is not None:
            by_run_id[manifest["run_id"]] = manifest
    with Path(path).open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != COLUMNS:
            return [f"the header must be exactly {list(COLUMNS)}, not {reader.fieldnames}"], counts
        seen: set[str] = set()
        for number, row in enumerate(reader, start=2):             # line 1 is the header
            run_id = row["run_id"].strip()
            if run_id in seen:
                problems.append(f"line {number}: run {run_id[:8]} appears twice")
            seen.add(run_id)
            if row["definition_notes"].strip():
                counts["notes"] += 1
            if is_blank(row):
                counts["unlabeled"] += 1
                continue
            counts["labeled"] += 1
            for error in telemetry.validate_record("label", row_to_record(row)):
                problems.append(f"line {number} (run {run_id[:8]}): {error}")
            manifest = by_run_id.get(run_id)
            if manifest is not None and not manifest.get("redacted", True):
                for secret_field, name in (("flag", "the flag"), ("admin_password", "the admin password")):
                    secret = manifest.get(secret_field)
                    if secret and secret in row["key_evidence"]:
                        problems.append(f"line {number} (run {run_id[:8]}): key_evidence contains {name}")
    return problems, counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    make = sub.add_parser("make")
    make.add_argument("run_dirs", nargs="*", type=Path)
    make.add_argument("--latest", type=int, help="label the N newest model runs under runs/")
    make.add_argument("--order-seed", type=int, help="label a batch's finished runs by run_order_seed (D-098), "
                                                      "not by recency")
    make.add_argument("--out", type=Path, default=DEFAULT_OUT)
    make.add_argument("--seed", type=int, default=0, help="the shuffle's seed (default 0)")
    make.add_argument("--runs-dir", type=Path, default=RUNS_DIR)
    check = sub.add_parser("check")
    check.add_argument("sheet", type=Path)
    check.add_argument("--runs-dir", type=Path, default=RUNS_DIR)
    args = parser.parse_args(argv)

    try:
        if args.command == "make":
            ids = make_sheet(pick_runs(args.run_dirs, args.latest, args.runs_dir, args.order_seed), args.out, args.seed)
            print(f"wrote {len(ids)} rows to {args.out} (shuffle seed {args.seed})")
            return 0
        problems, counts = check_sheet(args.sheet, args.runs_dir)
    except (ValueError, OSError) as err:
        print(err)
        return 2
    print(f"{counts['labeled']} labeled, {counts['unlabeled']} unlabeled, {counts['notes']} with a definition note")
    for problem in problems:
        print(f"  - {problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
