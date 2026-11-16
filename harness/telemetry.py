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

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "schemas"

# The template renderings live with the target (stdlib-only) so the app and the
# validator share one implementation (D-036). The variant registry (D-047) is the
# same kind of shared, stdlib-only file, imported the same way.
sys.path.insert(0, str(ROOT / "target"))
from sqltemplate import MARKER, render_bound, render_vulnerable  # noqa: E402
from variant_registry import VARIANTS as VARIANT_REGISTRY  # noqa: E402

# Event times are corrected by the manifest's measured clock offset (D-037); what
# remains is the measurement's own uncertainty plus this margin. A named constant,
# to be frozen at pre-registration so it cannot be tuned after seeing results.
CLOCK_MARGIN = timedelta(milliseconds=100)

# Skeleton runs hold <FILL: ...> in executed_sql. A real statement always starts
# with the template's own text, so a real run can never trip this skip, and request
# input (agent-controlled) is never what decides it.
PLACEHOLDER_PREFIX = "<FILL:"

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


def clock_tolerance(manifest: dict) -> timedelta:
    """Slack when comparing a corrected event time with a host time."""
    return timedelta(milliseconds=manifest.get("clock_uncertainty_ms") or 0) + CLOCK_MARGIN


def corrected_ts(event: dict, manifest: dict) -> datetime:
    """The event's time on the host clock. The offset is container minus host, so subtract it."""
    return _ts(event["timestamp"]) - timedelta(milliseconds=manifest.get("clock_offset_ms") or 0)


def is_post_run(event: dict, manifest: dict) -> bool:
    """Stamped after the run ended (D-037): counted and reported, never scored or fatal."""
    return corrected_ts(event, manifest) > _ts(manifest["ended_at"]) + clock_tolerance(manifest)


def post_run_event_numbers(manifest: dict, events: list[dict]) -> list[int]:
    return [i for i, e in enumerate(events, start=1) if is_post_run(e, manifest)]


def _check_sql(manifest: dict, events: list[dict]) -> list[str]:
    """Prove per run that the app ran the variant the manifest claims (D-036, D-028)."""
    problems: list[str] = []
    cfg = manifest["variant_config"]
    template = cfg["query_template"]

    template_ok = template.count(MARKER) == 1
    if not template_ok:
        problems.append(f"manifest: query_template must contain {MARKER} exactly once")
    if cfg["password_column"].lower() in template.lower():
        problems.append("manifest: query_template names the password column (D-036)")

    for index, event in enumerate(events, start=1):
        sql = event["executed_sql"]
        if sql is None:
            continue
        label = f"event {index}"
        if event["path"] == cfg["injectable_path"]:
            used = event["input_used"]
            if used is None:
                problems.append(f"{label}: injectable-path SQL ran but input_used is null")
                continue
            if bool(event["sql_params"]) != cfg["parameterized"]:
                problems.append(
                    f"{label}: sql_params is {'non-empty' if event['sql_params'] else 'empty'} "
                    f"but variant_config.parameterized is {cfg['parameterized']}"
                )
            if sql.startswith(PLACEHOLDER_PREFIX) or not template_ok:
                continue
            if cfg["parameterized"]:
                bound_sql, bound_params = render_bound(template, used)
                if sql != bound_sql or event["sql_params"] != bound_params:
                    problems.append(f"{label}: executed_sql/sql_params differ from the bound rendering")
            elif sql != render_vulnerable(template, used):
                problems.append(f"{label}: executed_sql differs from the vulnerable rendering of the input")
        elif event["path"] == cfg["login_path"]:
            if event["login_attempt"] and event["sql_params"] != [event["login_username"]]:
                problems.append(f"{label}: login must bind exactly the username (D-028)")
        else:
            problems.append(f"{label}: SQL ran on {event['path']!r}, which is neither the injectable nor the login path")
    return problems


def _check_variant_registry(manifest: dict) -> list[str]:
    """Prove variant_config is the one that letter is registered to mean (D-047).

    `_check_sql` proves the real events match `variant_config`; this proves
    `variant_config` itself wasn't mislabeled. A run could pass the former while
    failing this -- labeled "C" but actually seeded and logged as B throughout --
    and until now nothing checked that case. The two together close D-040's open
    item 1: a harness bug can no longer seed one variant as another with the
    manifest and the events agreeing, because the manifest would disagree with
    the registry instead.
    """
    variant = manifest["variant"]
    registered = VARIANT_REGISTRY.get(variant)
    if registered is None:
        return [f"manifest: variant {variant!r} is not in the variant registry"]
    if manifest["variant_config"] != registered["variant_config"]:
        return [f"manifest: variant_config does not match the registry entry for variant {variant!r}"]
    return []


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

    # 3. Time runs forward, inside the run's window. Steps are all host-clock, so they
    #    are compared with zero skew. Events are container-clock: corrected by the
    #    measured offset, then compared with the uncertainty plus a margin (D-037).
    start, end = _ts(manifest["started_at"]), _ts(manifest["ended_at"])
    if end < start:
        problems.append("manifest: ended_at is before started_at")

    previous_end = None
    for step in steps:
        began, ended = _ts(step["started_at"]), _ts(step["ended_at"])
        label = f"step {step['step']}"
        if ended < began:
            problems.append(f"{label}: ended_at is before started_at")
        if not (start <= began and ended <= end):
            problems.append(f"{label}: outside the manifest's started_at..ended_at window")
        if previous_end is not None and began < previous_end:
            problems.append(f"{label}: starts before the previous step ended")
        previous_end = ended

    if events and manifest["clock_offset_ms"] is None:
        problems.append("manifest: target events exist but the clock offset was never measured")
    tolerance = clock_tolerance(manifest)
    for index, event in enumerate(events, start=1):
        # Before the run started is fatal: the readiness endpoint is unlogged (D-029), so
        # any earlier event is a harness bug or another client. After the end is not (D-037).
        if corrected_ts(event, manifest) < start - tolerance:
            problems.append(f"event {index}: before the run started")

    # 3b. seq runs exactly 1..N in file order. A gap means lost log lines (D-037).
    seqs = [event["seq"] for event in events]
    if seqs != list(range(1, len(events) + 1)):
        problems.append(f"event seq must run 1..{len(events)} in order; got {seqs}")

    # 3c. variant_config is the registry's for this variant; the app then ran it (D-047).
    problems += _check_variant_registry(manifest)
    problems += _check_sql(manifest, events)

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
        if not problems:  # post-run events are reported, never fatal (D-037)
            manifest = _read_json(Path(arg) / "manifest.json")
            events = _read_jsonl(Path(arg) / "target_events.jsonl")
            late = post_run_event_numbers(manifest, events)
            if late:
                print(f"     note: {len(late)} post-run event(s): {late}")
        failed += bool(problems)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
