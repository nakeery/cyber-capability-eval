"""Validate run telemetry against the phase 1 schemas (schemas/*.schema.json).

A run directory holds:
    manifest.json          Run manifest          (required)
    steps.jsonl            one Step per line     (required)
    target_events.jsonl    one Target event/line (required)
    score.json             Score                 (optional until phase 3)
    intent.json            intended label        (fake and skeleton runs only)
    label.json             labeler verdict       (optional)

Two layers of checks:
  1. validate_record(): each record against its own schema.
  2. check_consistency(): rules that span records (a schema sees one record at a time).

Usage:
    .venv/Scripts/python harness/telemetry.py <run_dir> [<run_dir> ...]
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta
from functools import cache
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"

# Allowed clock difference between the host (step timestamps) and the target
# container (event timestamps). Docker Desktop's VM clock can drift slightly.
CLOCK_SKEW = timedelta(seconds=2)

# Record kind -> (schema file, JSON pointer inside it, or "" for the root).
KINDS = {
    "manifest": ("run_manifest.schema.json", ""),
    "step": ("step.schema.json", ""),
    "target_event": ("target_event.schema.json", ""),
    "score": ("score.schema.json", ""),
    "label": ("label.schema.json", ""),
    "intent": ("label.schema.json", "#/$defs/intent"),
}

# jsonschema only enforces "format": "date-time" with an extra package installed.
# A local checker keeps the dependency list short. Timestamps must carry a timezone.
FORMATS = FormatChecker(formats=())


@FORMATS.checks("date-time", raises=ValueError)
def _is_datetime(value: object) -> bool:
    if not isinstance(value, str):
        return True  # type errors are reported by "type", not here
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("timestamp has no timezone")
    return True


@cache
def _registry() -> Registry:
    resources = []
    for path in SCHEMA_DIR.glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)  # a broken schema fails loudly, once
        resources.append((schema["$id"], Resource.from_contents(schema)))
        resources.append((path.name, Resource.from_contents(schema)))
    return Registry().with_resources(resources)


@cache
def _validator(kind: str) -> Draft202012Validator:
    filename, pointer = KINDS[kind]
    base = _registry().contents(filename)["$id"]
    return Draft202012Validator(
        {"$ref": base + pointer}, registry=_registry(), format_checker=FORMATS
    )


def validate_record(kind: str, record: object) -> list[str]:
    """Return human-readable schema errors for one record ([] if valid)."""
    errors = sorted(_validator(kind).iter_errors(record), key=lambda e: list(e.absolute_path))
    return [f"{kind} {'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message}" for e in errors]


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise ValueError(f"{path.name}: not valid UTF-8") from None


def _read_json(path: Path) -> object:
    """Parse one JSON file. Any parse failure becomes a ValueError that names the file."""
    try:
        return json.loads(_read_text(path))
    except json.JSONDecodeError as err:
        raise ValueError(f"{path.name}: invalid JSON ({err.msg})") from None


def _read_jsonl(path: Path) -> list[object]:
    """Parse a JSONL file. A record ends at "\\n" and nowhere else: str.splitlines()
    would also cut at U+2028, U+0085 and friends, which JSON allows inside a string."""
    records = []
    for number, line in enumerate(_read_text(path).split("\n"), start=1):
        if line.strip():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as err:
                raise ValueError(f"{path.name} line {number}: invalid JSON ({err.msg})") from None
    return records


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


def check_consistency(manifest: dict, steps: list[dict], events: list[dict],
                      score: dict | None) -> list[str]:
    """Rules that span records. Return every problem found ([] if consistent).

    Collects instead of raising, like the rest of the validator, so one bad run
    reports all of its problems at once.
    """
    problems: list[str] = []
    run_id = manifest["run_id"]

    # 1. Every record belongs to this run.
    for step in steps:
        if step["run_id"] != run_id:
            problems.append(f"step {step['step']}: run_id differs from the manifest")
    for index, event in enumerate(events, start=1):
        if event["run_id"] != run_id:
            problems.append(f"event {index}: run_id differs from the manifest")
    if score is not None and score["run_id"] != run_id:
        problems.append("score: run_id differs from the manifest")

    # 2. Steps are numbered 1..N exactly once each, in file order.
    numbers = [step["step"] for step in steps]
    if numbers != list(range(1, len(steps) + 1)):
        missing = sorted(set(range(1, max(numbers, default=0) + 1)) - set(numbers))
        duplicates = sorted({n for n in numbers if numbers.count(n) > 1})
        problems.append(
            f"step numbers must run 1..{len(steps)} in order; "
            f"got {numbers} (missing {missing}, duplicated {duplicates})"
        )

    # 3. Time runs forward, inside the run's window. Target events are stamped by the
    #    container and steps by the host, so allow a little clock skew between them.
    start, end = _ts(manifest["started_at"]), _ts(manifest["ended_at"])
    if end < start:
        problems.append("manifest: ended_at is before started_at")
    window_lo, window_hi = start - CLOCK_SKEW, end + CLOCK_SKEW

    previous_end = None
    for step in steps:
        began, ended = _ts(step["started_at"]), _ts(step["ended_at"])
        label = f"step {step['step']}"
        if ended < began:
            problems.append(f"{label}: ended_at is before started_at")
        if not (window_lo <= began and ended <= window_hi):
            problems.append(f"{label}: outside the manifest's started_at..ended_at window")
        if previous_end is not None and began < previous_end - CLOCK_SKEW:
            problems.append(f"{label}: starts before the previous step ended")
        previous_end = ended
    for index, event in enumerate(events, start=1):
        if not window_lo <= _ts(event["timestamp"]) <= window_hi:
            problems.append(f"event {index}: outside the manifest's started_at..ended_at window")

    # 4. One-shot submission (D-001): at most one submit_flag, it is the last step,
    #    and it is the run's ending exactly when termination_reason says so.
    submits = [step["step"] for step in steps if step["tool_name"] == "submit_flag"]
    if len(submits) > 1:
        problems.append(f"submit_flag called {len(submits)} times (steps {submits}); it is one-shot")
    if submits and submits[-1] != len(steps):
        problems.append(f"step {submits[-1]}: submit_flag must be the last step")
    if (manifest["termination_reason"] == "submitted") != bool(submits):
        problems.append(
            f"termination_reason is {manifest['termination_reason']!r} but "
            f"{'a' if submits else 'no'} submit_flag step exists"
        )
    if score is not None and score["flag_submitted"] != bool(submits):
        problems.append("score: flag_submitted disagrees with the step log")

    return problems


def validate_run_dir(run_dir: Path) -> list[str]:
    """Validate every record in one run directory, then the cross-record rules."""
    problems: list[str] = []
    try:
        manifest = _read_json(run_dir / "manifest.json")
        steps = _read_jsonl(run_dir / "steps.jsonl")
        events = _read_jsonl(run_dir / "target_events.jsonl")
    except (OSError, ValueError) as err:
        return [str(err)]

    problems += validate_record("manifest", manifest)
    for step in steps:
        # A line can be valid JSON without being an object; the schema reports that.
        number = step.get("step", "?") if isinstance(step, dict) else "?"
        problems += [f"step {number}: {p}" for p in validate_record("step", step)]
    for index, event in enumerate(events, start=1):
        problems += [f"event {index}: {p}" for p in validate_record("target_event", event)]

    score = None
    for name, kind in (("score.json", "score"), ("intent.json", "intent"), ("label.json", "label")):
        path = run_dir / name
        if not path.exists():
            continue
        try:
            record = _read_json(path)
        except (OSError, ValueError) as err:
            problems.append(str(err))  # report it and carry on, like every other problem
            continue
        problems += validate_record(kind, record)
        if kind == "score":
            score = record

    if not problems:  # cross-record rules assume each record is individually valid
        problems += check_consistency(manifest, steps, events, score)
    return problems


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    failed = 0
    for arg in argv:
        problems = validate_run_dir(Path(arg))
        print(f"{'OK  ' if not problems else 'FAIL'} {arg}")
        for problem in problems:
            print(f"     - {problem}")
        failed += bool(problems)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
