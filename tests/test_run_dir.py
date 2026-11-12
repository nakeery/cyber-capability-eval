"""validate_run_dir: the on-disk layout, end to end."""

import json

from telemetry import main, validate_run_dir


def write_run(path, manifest, steps, events, **extra):
    path.mkdir()
    (path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (path / "steps.jsonl").write_text("".join(json.dumps(s) + "\n" for s in steps), encoding="utf-8")
    (path / "target_events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    for name, record in extra.items():
        (path / f"{name}.json").write_text(json.dumps(record), encoding="utf-8")
    return path


def test_valid_run_dir(tmp_path, manifest, step, event, score, label):
    run = write_run(tmp_path / "run", manifest, [step], [event], score=score, label=label)
    assert validate_run_dir(run) == []
    assert main([str(run)]) == 0


def test_missing_file_is_reported(tmp_path, manifest, step, event):
    run = write_run(tmp_path / "run", manifest, [step], [event])
    (run / "steps.jsonl").unlink()
    assert any("steps.jsonl" in p for p in validate_run_dir(run))


def test_bad_json_line_names_the_line(tmp_path, manifest, step, event):
    run = write_run(tmp_path / "run", manifest, [step], [event])
    with open(run / "steps.jsonl", "a", encoding="utf-8") as fh:
        fh.write("{not json\n")
    assert any("steps.jsonl line 2" in p for p in validate_run_dir(run))


def test_schema_error_skips_cross_record_checks(tmp_path, manifest, step, event):
    step["step"] = 0  # schema error; consistency checks would add noise on top
    run = write_run(tmp_path / "run", manifest, [step], [event])
    problems = validate_run_dir(run)
    assert problems and all(p.startswith("step 0: step") for p in problems), problems
    assert main([str(run)]) == 1


def test_bad_intent_file_is_reported(tmp_path, manifest, step, event, intent):
    intent["intended_label"] = "PROBABLY_FINE"
    run = write_run(tmp_path / "run", manifest, [step], [event], intent=intent)
    assert any(p.startswith("intent") for p in validate_run_dir(run))
