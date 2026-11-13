"""validate_run_dir: the on-disk layout, end to end."""

import json

import pytest
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


# --- malformed input is reported, never raised --------------------------------

def test_bad_json_in_manifest_names_the_file(tmp_path, manifest, step, event):
    run = write_run(tmp_path / "run", manifest, [step], [event])
    (run / "manifest.json").write_text("{bad", encoding="utf-8")
    assert any("manifest.json: invalid JSON" in p for p in validate_run_dir(run))


def test_bad_json_in_an_optional_file_is_reported(tmp_path, manifest, step, event, score):
    run = write_run(tmp_path / "run", manifest, [step], [event], score=score)
    (run / "score.json").write_text("{bad", encoding="utf-8")
    assert any("score.json: invalid JSON" in p for p in validate_run_dir(run))


def test_one_bad_run_does_not_stop_the_batch(tmp_path, capsys, manifest, step, event, score):
    bad = write_run(tmp_path / "bad", manifest, [step], [event], score=score)
    (bad / "score.json").write_text("{bad", encoding="utf-8")
    good = write_run(tmp_path / "good", manifest, [step], [event])
    assert main([str(bad), str(good)]) == 1
    out = capsys.readouterr().out
    assert f"FAIL {bad}" in out
    assert f"OK   {good}" in out  # the run after the bad one was still checked


def test_non_object_jsonl_line_is_reported(tmp_path, manifest, step, event):
    run = write_run(tmp_path / "run", manifest, [step], [event])
    (run / "steps.jsonl").write_text("5\n", encoding="utf-8")  # valid JSON, not a record
    problems = validate_run_dir(run)
    assert any("is not of type 'object'" in p for p in problems), problems


@pytest.mark.parametrize("separator", [" ", "\x85"])
def test_unicode_line_separators_do_not_split_a_record(tmp_path, manifest, step, event, separator):
    # JSONL records end at "\n" only. ensure_ascii=False keeps these separators raw
    # inside a string (as a harness writer might), and str.splitlines() would cut there.
    step["output_full"] = step["output_sent_to_model"] = f"before{separator}after"
    run = write_run(tmp_path / "run", manifest, [step], [event])
    (run / "steps.jsonl").write_text(json.dumps(step, ensure_ascii=False) + "\n", encoding="utf-8")
    assert validate_run_dir(run) == []
