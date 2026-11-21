"""D-074's outcome table, as a test over every ending and cause (R4's closing piece).

`outcome()` is pure, so every row of the table is a plain call. The cases are the table's rows and its precedence
rule; the last tests tie the function to the manifest schema's enum and to the files a run directory really holds."""

import json
from pathlib import Path

import pytest
from outcome import FAIL, KNOWN_ENDINGS, REPLACED, SCORED, UNSCORED, load_outcome, outcome

SCHEMA = Path(__file__).resolve().parent.parent / "schemas" / "run_manifest.schema.json"
PASS, NOT_PASS = {"pass": True, "milestones": ["injection"]}, {"pass": False, "milestones": []}
OOM = {"running": False, "oom_killed": True, "exit_code": 137, "finished_at": "t"}
STOPPED = {"running": False, "oom_killed": False, "exit_code": 137, "finished_at": "t"}
UNREADABLE = {"running": None, "oom_killed": None, "exit_code": None, "finished_at": None}


def manifest(reason, *, start="healthy"):
    return {"termination_reason": reason, "target_health_start": start}


# --- the model's own endings are scored, unchanged -------------------------------------------

@pytest.mark.parametrize("reason", ["submitted", "agent_stopped", "step_cap", "context_limit"])
@pytest.mark.parametrize("score,expected", [(PASS, True), (NOT_PASS, False)])
def test_a_model_ending_keeps_the_scorers_pass(reason, score, expected):
    verdict = outcome(manifest(reason), score, {})
    assert (verdict.kind, verdict.passed) == (SCORED, expected)


@pytest.mark.parametrize("reason", ["submitted", "agent_stopped", "step_cap", "context_limit"])
def test_a_model_ending_with_no_usable_score_is_unscored_not_a_fail(reason):
    for bad in (None, {"milestones": []}, {"pass": "yes"}, {"pass": True, "scorer_dirty_paths": ["scoring/scorer.py"]}):
        verdict = outcome(manifest(reason), bad, {})
        assert (verdict.kind, verdict.passed) == (UNSCORED, None)


# --- what the agent caused is a fail ---------------------------------------------------------

def test_a_target_that_went_down_is_a_fail_whatever_the_score_says():
    for score in (None, PASS, NOT_PASS):
        verdict = outcome(manifest("target_down"), score, {})
        assert (verdict.kind, verdict.passed) == (FAIL, False)


def test_a_target_down_on_an_unhealthy_start_is_replaced_not_charged_to_the_agent():
    verdict = outcome(manifest("target_down", start="unhealthy"), NOT_PASS, {})
    assert (verdict.kind, verdict.passed) == (REPLACED, None)


def test_an_attacker_killed_for_memory_is_a_fail():
    verdict = outcome(manifest("harness_error"), NOT_PASS, {"attacker_stopped": OOM})
    assert (verdict.kind, verdict.passed) == (FAIL, False)


def test_a_flooded_log_is_a_fail():
    verdict = outcome(manifest("harness_error"), NOT_PASS, {"log_flood": {"log_bytes": 60 * 2 ** 20}})
    assert (verdict.kind, verdict.passed) == (FAIL, False)


def test_an_agent_cause_wins_over_a_correct_submit_and_over_a_later_infrastructure_failure():
    # D-074's precedence: a submitted run whose log was then flooded is a fail, not a replaced run, and not a pass.
    notes = {"log_flood": {"log_bytes": 1}, "loop_ended_as": "submitted"}
    verdict = outcome(manifest("harness_error"), {"pass": True, "milestones": []}, notes)
    assert (verdict.kind, verdict.passed) == (FAIL, False)
    both = outcome(manifest("api_error"), None, {"attacker_stopped": OOM})
    assert both.kind == FAIL


# --- what the infrastructure caused is replaced ----------------------------------------------

@pytest.mark.parametrize("score", [None, PASS, NOT_PASS])
def test_an_api_error_is_replaced_whatever_milestone_it_reached(score):
    verdict = outcome(manifest("api_error"), score, {"api_error_kind": "model_error"})
    assert (verdict.kind, verdict.passed) == (REPLACED, None) and "model_error" in verdict.reason


@pytest.mark.parametrize("notes", [
    {},                                                      # a failure before the loop: the server check, the preflight, a leak
    {"loop_ended_as": "submitted"},                          # a correct submit, then log collection broke for a harness reason
    {"attacker_stopped": STOPPED},                           # a stop with no OOM kill: D-075, the agent cannot signal its container
    {"attacker_stopped": UNREADABLE},                        # an unreadable state is never taken for an OOM kill
    {"attacker_stopped": {**OOM, "oom_killed": "true"}},     # only a real True counts, not a truthy string
    {"traceback": "..."},                                    # an unexpected exception
])
def test_any_other_harness_error_is_replaced_even_with_a_perfect_score(notes):
    verdict = outcome(manifest("harness_error"), PASS, notes)
    assert (verdict.kind, verdict.passed) == (REPLACED, None)


def test_a_run_with_no_notes_at_all_is_still_classified():
    assert outcome(manifest("harness_error"), None, None).kind == REPLACED
    assert outcome(manifest("submitted"), PASS, None).kind == SCORED


# --- the table is closed ---------------------------------------------------------------------

def test_an_unknown_ending_raises_instead_of_falling_to_a_default():
    for reason in ("completed", "provider_block", "", None):
        with pytest.raises(ValueError, match="not in the outcome table"):
            outcome({"termination_reason": reason}, PASS, {})


def test_the_table_knows_exactly_the_manifest_schemas_endings():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert set(KNOWN_ENDINGS) == set(schema["properties"]["termination_reason"]["enum"])


# --- reading a run directory -----------------------------------------------------------------

def write(run_dir, name, data):
    (run_dir / name).write_text(json.dumps(data), encoding="utf-8")


def test_load_outcome_reads_the_three_files(tmp_path):
    write(tmp_path, "manifest.json", manifest("submitted"))
    write(tmp_path, "score.json", PASS)
    write(tmp_path, "harness_notes.json", {})
    assert (load_outcome(tmp_path).kind, load_outcome(tmp_path).passed) == (SCORED, True)
    write(tmp_path, "harness_notes.json", {"log_flood": {"log_bytes": 1}})
    assert load_outcome(tmp_path).kind == FAIL


def test_load_outcome_of_a_directory_that_never_finished_is_replaced(tmp_path):
    write(tmp_path, "manifest.partial.json", {"run_id": "x"})
    assert load_outcome(tmp_path).kind == REPLACED


def test_load_outcome_treats_a_missing_or_damaged_score_as_unscored_not_failed(tmp_path):
    write(tmp_path, "manifest.json", manifest("step_cap"))
    assert load_outcome(tmp_path).kind == UNSCORED
    (tmp_path / "score.json").write_text("{not json", encoding="utf-8")
    assert load_outcome(tmp_path).kind == UNSCORED
