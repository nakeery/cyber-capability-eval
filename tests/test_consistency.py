"""Cross-record rules: things no single schema can see.

Each test starts from a consistent two-step run and breaks exactly one rule.
"""

import pytest
from conftest import T1, T2
from telemetry import check_consistency

OTHER_RUN = "ffffffffffffffffffffffffffffffff"
T_MID = "2026-11-12T10:00:06+00:00"  # between step 1's end and the run's end


@pytest.fixture
def steps(step):
    second = {**step, "step": 2, "started_at": T_MID, "ended_at": T2, "bedrock_request_id": "req-2"}
    return [step, second]


def problems_for(manifest, steps, events, score):
    return check_consistency(manifest, steps, events, score)


def assert_reports(problems, fragment):
    assert any(fragment in p for p in problems), problems


# --- baseline ----------------------------------------------------------------

def test_consistent_run_has_no_problems(manifest, steps, event, score):
    assert problems_for(manifest, steps, [event], score) == []


def test_score_is_optional(manifest, steps, event):
    assert problems_for(manifest, steps, [event], None) == []


# --- 1. records belong to this run -----------------------------------------------

def test_step_from_another_run_is_reported(manifest, steps, event, score):
    steps[0]["run_id"] = OTHER_RUN
    assert_reports(problems_for(manifest, steps, [event], score), "step 1: run_id")


def test_event_from_another_run_is_reported(manifest, steps, event, score):
    event["run_id"] = OTHER_RUN
    assert_reports(problems_for(manifest, steps, [event], score), "event 1: run_id")


def test_score_from_another_run_is_reported(manifest, steps, event, score):
    score["run_id"] = OTHER_RUN
    assert_reports(problems_for(manifest, steps, [event], score), "score: run_id")


# --- 2. step numbering -----------------------------------------------------------

def test_missing_step_number_is_reported(manifest, steps, event, score):
    steps[1]["step"] = 3
    assert_reports(problems_for(manifest, steps, [event], score), "missing [2]")


def test_duplicate_step_number_is_reported(manifest, steps, event, score):
    steps[1]["step"] = 1
    assert_reports(problems_for(manifest, steps, [event], score), "duplicated [1]")


# --- 3. time -------------------------------------------------------------------

def test_step_ending_before_it_starts_is_reported(manifest, steps, event, score):
    steps[1]["ended_at"] = T_MID.replace(":06", ":05")
    assert_reports(problems_for(manifest, steps, [event], score), "step 2: ended_at is before")


def test_overlapping_steps_are_reported(manifest, steps, event, score):
    steps[1]["started_at"] = "2026-11-12T10:00:01+00:00"  # 4 s before step 1 ended
    assert_reports(problems_for(manifest, steps, [event], score), "starts before the previous step")


def test_event_outside_the_run_window_is_reported(manifest, steps, event, score):
    event["timestamp"] = "2026-11-12T10:05:00+00:00"
    assert_reports(problems_for(manifest, steps, [event], score), "event 1: outside")


def test_small_clock_skew_is_tolerated(manifest, steps, event, score):
    event["timestamp"] = "2026-11-12T10:00:10+00:00"  # 1 s after ended_at, within 2 s
    assert problems_for(manifest, steps, [event], score) == []


# --- 4. one-shot submission (D-001) ------------------------------------------

def submit(step):
    step.update(tool_name="submit_flag", tool_input={"flag": "x"}, exit_code=None,
                output_full="Submission received.", output_sent_to_model="Submission received.")


def test_submitted_run_with_final_submit_is_consistent(manifest, steps, event, score):
    submit(steps[1])
    manifest["termination_reason"] = "submitted"
    score["flag_submitted"] = True
    assert problems_for(manifest, steps, [event], score) == []


def test_submit_flag_must_be_the_last_step(manifest, steps, event, score):
    submit(steps[0])
    manifest["termination_reason"] = "submitted"
    score["flag_submitted"] = True
    assert_reports(problems_for(manifest, steps, [event], score), "must be the last step")


def test_second_submission_is_reported(manifest, steps, event, score):
    submit(steps[0])
    submit(steps[1])
    manifest["termination_reason"] = "submitted"
    score["flag_submitted"] = True
    assert_reports(problems_for(manifest, steps, [event], score), "one-shot")


def test_termination_reason_must_match_the_step_log(manifest, steps, event, score):
    manifest["termination_reason"] = "submitted"  # but no submit_flag step
    assert_reports(problems_for(manifest, steps, [event], score), "no submit_flag step")


def test_score_must_match_the_step_log(manifest, steps, event, score):
    score["flag_submitted"] = True  # but no submit_flag step
    assert_reports(problems_for(manifest, steps, [event], score), "score: flag_submitted")
