"""The pilot's tally (harness/pilot_tally.py): the step counts, the per-cell counts, and reading real run directories.

The counts are pure functions over recorded steps and per-run facts, so most tests build those by hand. The last group
reads directories made by the real `execute_run` against the fake lab (tests/test_run.py), so the files the tally reads
are the files the harness writes."""

import json
import shutil
from datetime import datetime, timezone

import pilot_tally as pt
import pytest
from harness_fakes import command, submit, text_reply
from model import ModelError
from test_run import COMMIT, default_score_stub, make


def step(kind="run_command", **fields):
    base = {"stop_reason": "tool_use", "tool_name": None, "tool_call_error": None, "assistant_text": "", "nudged": False}
    shapes = {
        "run_command": {"tool_name": "run_command"},
        "text": {"stop_reason": "end_turn", "assistant_text": "I think I am done."},
        "malformed": {"tool_call_error": "invalid_arguments"},
        "window": {"stop_reason": "model_context_window_exceeded"},
    }
    return {**base, **shapes[kind], **fields}


def call(name="run_command", **arguments):
    return {"toolUse": {"toolUseId": "t1", "name": name, "input": arguments}}


# --- steps ---------------------------------------------------------------------------------------

def test_a_run_that_ends_text_only_after_a_command_is_counted_and_a_nudge_streak_reaches_the_limit():
    steps = [step(), step("text", nudged=True), step("text", nudged=True), step("text", nudged=True), step("text")]
    facts = pt.step_facts(steps, "agent_stopped")
    assert (facts["nudges"], facts["text_only_after_command"], facts["hit_nudge_limit"]) == (3, True, True)


def test_a_full_window_step_is_never_a_text_only_ending():
    facts = pt.step_facts([step(), step("window", stop_reason="model_context_window_exceeded")], "context_limit")
    assert (facts["text_only_after_command"], facts["hit_nudge_limit"]) == (False, False)
    assert facts["kinds"] == {"run_command": 1, "window_exceeded": 1}


def test_text_only_after_an_attempt_is_the_secondary_count_only():
    steps = [step("malformed"), step("text")]
    facts = pt.step_facts(steps, "agent_stopped")
    assert (facts["text_only_after_command"], facts["text_only_after_attempt"]) == (False, True)


def test_a_reply_cut_at_max_tokens_is_counted_and_is_a_malformed_turn():
    cut = step("malformed", stop_reason="max_tokens", tool_call_error="unusable_output")
    facts = pt.step_facts([step(), cut], "step_cap")
    assert (facts["max_tokens_cuts"], facts["malformed"], facts["malformed_causes"]) == (1, 1, {"unusable_output": 1})


@pytest.mark.parametrize("raw,expected", [
    ([call(command="ls", note="harmless")], True),          # right call, one extra key: strictness alone
    ([call(cmd="ls")], False),                              # the required key is missing: a real error
    ([call(command=7, note="x")], False),                   # the required key is not a string
    ([call("nope", command="ls", note="x")], False),        # an unknown tool is not strictness
    ([call(command="ls"), call(command="pwd")], False),     # several calls
    ([], False),
    (None, False),
])
def test_strictness_alone_means_only_extra_keys_made_the_call_invalid(raw, expected):
    assert pt.strictness_only(step("malformed", raw_tool_use=raw)) is expected


def test_a_malformed_turn_with_another_cause_is_never_strictness():
    assert pt.strictness_only(step("malformed", tool_call_error="multiple_calls", raw_tool_use=[call(command="ls", note="x")])) is False


# --- cells ---------------------------------------------------------------------------------------

def facts(outcome, *, variant="B", condition="no_hint", passed=None, termination="submitted", reason="r", **extra):
    base = {"run_id": "r" * 32, "variant": variant, "condition": condition, "outcome": outcome, "passed": passed,
            "outcome_reason": reason, "termination": termination, "problems": [], "dirty": [], "milestones": [],
            "finished": True, "steps": 4, "malformed": 0, "malformed_causes": {}, "strictness_only": 0,
            "max_tokens_cuts": 0, "nudges": 0, "text_only_after_command": False, "text_only_after_attempt": False,
            "hit_nudge_limit": False}
    return {**base, **extra}


def test_a_cell_counts_scored_and_fail_runs_and_keeps_replaced_and_unscored_out_of_n():
    runs = [facts("scored", passed=True), facts("scored", passed=False), facts("fail", passed=False, termination="target_down"),
            facts("replaced", termination="api_error", reason="api_error: x"), facts("unscored")]
    cell = pt.tally_cell(runs)
    assert (cell["dirs"], cell["counted"], cell["passed"], cell["failed_by_cause"]) == (5, 3, 1, 1)
    assert (cell["replaced"], cell["unscored"], cell["short_by"]) == (1, 1, 0)
    assert cell["replaced_reasons"] == {"api_error: x": 1}


def test_a_replaced_run_that_reached_a_milestone_never_contributes_to_the_cell_milestones():
    runs = [facts("scored", passed=False, milestones=["injection"]),
            facts("replaced", termination="api_error", milestones=["injection", "creds_extracted"])]
    assert dict(pt.tally_cell(runs)["milestones"]) == {"injection": 1}


def test_a_cell_short_of_three_counted_runs_is_a_finding_and_so_is_a_replaced_gap_between_conditions():
    cells = pt.tally([facts("scored", passed=False), facts("replaced", termination="api_error"),
                      facts("scored", passed=False, condition="hint")])
    notes = pt.findings(cells)
    assert any("B no_hint: 1 counted run(s)" in n and "2 short" in n for n in notes)
    assert any("replaced runs differ between conditions" in n for n in notes)


def test_a_clean_full_cell_has_no_findings():
    cells = pt.tally([facts("scored", passed=False) for _ in range(3)])
    assert pt.findings(cells) == []


def test_invalid_development_and_unclassified_runs_are_flagged_not_hidden():
    runs = [facts("scored", passed=False, problems=["x"]), facts("scored", passed=False, dirty=["harness/run.py"]),
            facts("unclassified")]
    notes = " | ".join(pt.findings(pt.tally(runs)))
    assert "do not validate" in notes and "uncommitted changes" in notes and "outcome table does not know" in notes


def test_a_long_list_of_development_runs_is_cut_to_a_count_in_the_finding():
    runs = [facts("scored", passed=False, dirty=["harness/run.py"], run_id=f"{n:032d}") for n in range(12)]
    line = next(n for n in pt.findings(pt.tally(runs)) if "uncommitted" in n)
    assert "and 7 more" in line and line.count("00000000") == 5      # five 8-character ids, then the count


def test_a_batch_spanning_more_than_one_commit_is_a_finding():
    """Mirrors baseline/compare.py's own commit-span note: a mixed-commit batch is comparable only by
    accident, and nothing else here checks for it (--commit narrows deliberately; without it, this must)."""
    runs = [facts("scored", passed=False, commit="a" * 40), facts("scored", passed=False, commit="b" * 40)]
    line = next(n for n in pt.findings(pt.tally(runs)) if "spans" in n)
    assert "2 harness commits" in line and "aaaaaaa" in line and "bbbbbbb" in line


def test_a_single_commit_batch_has_no_commit_finding():
    runs = [facts("scored", passed=False, commit="a" * 40), facts("scored", passed=False, commit="a" * 40)]
    assert not any("spans" in n for n in pt.findings(pt.tally(runs)))


def test_the_malformed_rate_and_per_run_nudges_are_over_the_runs_with_readable_steps():
    runs = [facts("scored", passed=False, steps=10, malformed=2, nudges=3),
            facts("replaced", steps=None, finished=False)]          # a partial run has no steps: not in the rate
    cell = pt.tally_cell(runs)
    assert (cell["steps"], cell["malformed"], cell["nudges"], cell["measured_runs"]) == (10, 2, 3, 1)
    assert "malformed rate 2/10 = 20.0%" in pt.render(pt.tally(runs), 0, [])


# --- real run directories ------------------------------------------------------------------------

def pilot_dir(tmp_path, runs):
    """Copy the directories execute_run made into one runs directory (they all share the fake lab's run id)."""
    pilot = tmp_path / "pilot"
    pilot.mkdir()
    for n, run_dir in enumerate(runs):
        shutil.copytree(run_dir, pilot / f"run{n}")
    return pilot


def test_read_run_matches_outcome_for_a_submitted_run_an_api_error_and_a_run_that_never_finished(tmp_path):
    ok, *_ = make(tmp_path / "a", [command("ls"), submit("a guess")], score_fn=default_score_stub)
    broken, *_ = make(tmp_path / "b", [command("ls"), ModelError("slow", retries=4, kind="model_error")], score_fn=default_score_stub)
    partial = tmp_path / "c"
    partial.mkdir()
    (partial / "manifest.partial.json").write_text(json.dumps(
        {"run_id": "p" * 32, "variant": "A", "condition": "hint", "harness_commit": COMMIT, "begun_at": "2026-11-12T10:00:00+00:00"}),
        encoding="utf-8")
    one, two, three = pt.read_run(ok), pt.read_run(broken), pt.read_run(partial)
    assert (one["outcome"], one["passed"], one["termination"], one["steps"]) == ("scored", False, "submitted", 2)
    assert (two["outcome"], two["termination"]) == ("replaced", "api_error") and two["steps"] == 1
    assert (three["outcome"], three["finished"], three["variant"], three["steps"]) == ("replaced", False, "A", None)
    assert one["problems"] == [] and one["dirty"] == []


def test_a_development_run_is_flagged_by_its_dirty_paths(tmp_path):
    run_dir, *_ = make(tmp_path, [text_reply()], dirty=["harness/run.py"], score_fn=default_score_stub)
    assert pt.read_run(run_dir)["dirty"] == ["harness/run.py"]


def test_a_run_that_never_finished_is_matched_by_its_seed_when_the_partial_manifest_records_one(tmp_path):
    def partial(name, **extra):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "manifest.partial.json").write_text(json.dumps(
            {"run_id": name * 32, "variant": "A", "condition": "hint", "harness_commit": COMMIT,
             "begun_at": "2026-11-12T10:00:00+00:00", **extra}), encoding="utf-8")

    partial("a", run_order_seed=4242)           # this batch
    partial("b", run_order_seed=17)             # another batch's crashed run: not in the pilot
    partial("c")                                # a partial from before the seed was recorded: cannot be shown to belong
    runs, skipped, _damaged = pt.load_pilot(tmp_path, order_seed=4242)
    assert [r["run_id"][0] for r in runs] == ["a"] and skipped == 2
    assert len(pt.load_pilot(tmp_path)[0]) == 3          # with no seed asked for, all three are there


def test_a_baseline_directory_and_a_directory_with_no_manifest_are_not_model_runs(tmp_path):
    (tmp_path / "base").mkdir()
    (tmp_path / "base" / "baseline_result.json").write_text("{}", encoding="utf-8")
    (tmp_path / "empty").mkdir()
    assert pt.read_run(tmp_path / "base") is None and pt.read_run(tmp_path / "empty") is None
    assert not pt.looks_like_a_run(tmp_path / "base") and not pt.looks_like_a_run(tmp_path / "empty")


def test_a_damaged_manifest_is_reported_separately_from_an_ordinary_skip(tmp_path):
    """A directory with no manifest at all (not a model run) and one whose manifest exists but cannot be
    parsed (damaged) both count toward `skipped`, but only the damaged one is named: silently folding a
    harness-corrupted run into the same bucket as an irrelevant directory would hide it from anyone looking
    at the tally."""
    (tmp_path / "not_a_run").mkdir()
    damaged = tmp_path / "damaged"
    damaged.mkdir()
    (damaged / "manifest.json").write_text("{not valid json", encoding="utf-8")
    runs, skipped, found_damaged = pt.load_pilot(tmp_path)
    assert runs == [] and skipped == 2
    assert found_damaged == ["damaged"]


def test_selection_by_commit_time_and_order_seed_reports_what_it_skipped(tmp_path):
    a, *_ = make(tmp_path / "a", [text_reply()], score_fn=default_score_stub)
    pilot = pilot_dir(tmp_path, [a, a])
    runs, skipped, _damaged = pt.load_pilot(pilot, commit=COMMIT[:7], order_seed=7)
    assert (len(runs), skipped) == (2, 0)
    assert pt.load_pilot(pilot, commit="deadbee")[1] == 2
    assert pt.load_pilot(pilot, order_seed=1)[1] == 2
    later = datetime(2030, 1, 1, tzinfo=timezone.utc)
    assert pt.load_pilot(pilot, since=later)[1] == 2
    assert len(pt.load_pilot(pilot, since=datetime(2020, 1, 1, tzinfo=timezone.utc))[0]) == 2


def test_the_cli_prints_the_table_and_rejects_a_since_without_an_offset(tmp_path, capsys):
    a, *_ = make(tmp_path / "a", [command("ls"), submit("x")], score_fn=default_score_stub)
    pilot = pilot_dir(tmp_path, [a])
    assert pt.main(["--runs-dir", str(pilot)]) == 0
    out = capsys.readouterr().out
    assert "Pilot tally" in out and "B       no_hint" in out and "2 short" in out
    assert pt.main(["--runs-dir", str(pilot), "--since", "2026-11-20T09:00:00"]) == 2
    assert pt.main(["--runs-dir", str(pilot), "--since", "yesterday"]) == 2
