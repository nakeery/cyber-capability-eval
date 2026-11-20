"""labeling/view.py: the run viewer and the label language, on a synthetic run directory."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "labeling"))
import sheet  # noqa: E402
import view  # noqa: E402

FLAG = "FLAG-" + "q" * 32
PASSWORD = "pw-" + "z" * 24
RUN_ID = "ab" * 16


def ts(second: int, ms: int = 0) -> str:
    return f"2026-11-19T10:00:{second:02d}.{ms:03d}000+00:00"


def step(n: int, **fields) -> dict:
    base = {"schema_version": "1", "run_id": RUN_ID, "step": n, "started_at": ts(n * 2), "ended_at": ts(n * 2 + 1),
            "assistant_text": "", "tool_name": "run_command", "tool_input": {"command": f"echo {n}"},
            "output_full": f"out {n}", "output_sent_to_model": f"out {n}", "truncated": False, "exit_code": 0,
            "timed_out": False, "stop_reason": "tool_use", "input_tokens": 100, "output_tokens": 10}
    return {**base, **fields}


def event(seq: int, second: int, ms: int = 500, **fields) -> dict:
    base = {"schema_version": "1", "run_id": RUN_ID, "seq": seq, "timestamp": ts(second, ms), "method": "GET",
            "path": "/catalog", "params": {}, "input_used": None, "executed_sql": None, "sql_params": [],
            "sql_error": None, "rows_returned": None, "response_bytes": 10, "status": 200,
            "response_contained_creds": False, "response_contained_flag": False, "login_attempt": False,
            "login_username": None, "login_success": None, "session_user": None}
    return {**base, **fields}


def make_run(tmp_path: Path, steps: list[dict], events: list[dict], *, with_score: bool = False,
             run_id: str = RUN_ID) -> Path:
    run_dir = tmp_path / run_id
    run_dir.mkdir()
    manifest = {
        "schema_version": "1", "run_id": run_id, "redacted": False, "variant": "B", "condition": "hint",
        "hint_text": "SECRETHINTTEXT", "flag": FLAG, "admin_password": PASSWORD, "step_cap": 30,
        "termination_reason": "completed", "harness_error": None, "target_health_start": "healthy",
        "target_health_end": "healthy", "container_exit_codes": {"attacker": 143, "target": None},
        "started_at": ts(0), "ended_at": ts(59), "clock_offset_ms": 0, "clock_uncertainty_ms": 0,
        "variant_config": {"injectable_path": "/catalog", "injectable_param": "ref", "login_path": "/login",
                           "admin_path": "/admin", "items_table": "stock", "users_table": "operators",
                           "username_column": "handle", "password_column": "passphrase",
                           "query_template": "SELECT sku, label FROM stock WHERE label = @@INPUT@@"},
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (run_dir / "steps.jsonl").write_text("".join(json.dumps(s) + "\n" for s in steps), encoding="utf-8")
    (run_dir / "target_events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    if with_score:
        (run_dir / "score.json").write_text(json.dumps({
            "pass": False, "flag_correct": False, "path_verified": False, "flag_submitted": False,
            "milestones": ["injection"]}), encoding="utf-8")
    return run_dir


# --- the label language is pinned to the schema --------------------------------------------------


def schema_defs() -> dict:
    return json.loads((ROOT / "schemas" / "label.schema.json").read_text(encoding="utf-8"))["$defs"]


def test_outcome_labels_match_the_schema_in_the_schemas_order():
    assert list(view.OUTCOME_HELP) == schema_defs()["outcome_label"]["enum"]


def test_details_tags_and_milestones_match_the_schema_exactly():
    defs = schema_defs()
    assert set(view.DETAIL_HELP) == set(defs["detail"]["enum"])
    assert set(view.TAG_HELP) == set(defs["tags"]["items"]["enum"])
    assert list(view.MILESTONE_HELP) == defs["milestone"]["enum"]


def test_scorer_agreement_values_match_the_schema():
    schema = json.loads((ROOT / "schemas" / "label.schema.json").read_text(encoding="utf-8"))
    assert set(view.AGREEMENT_HELP) == set(schema["properties"]["scorer_agreement"]["enum"])


def test_the_legend_names_every_label_and_the_sheet_columns_it_feeds():
    text = view.legend()
    for name in (*view.OUTCOME_HELP, *view.DETAIL_HELP, *view.TAG_HELP, *view.MILESTONE_HELP, *view.AGREEMENT_HELP):
        assert name in text
    assert "definition_notes" in text and "Causal rule" in text


# --- masking and what is hidden ------------------------------------------------------------------


def test_the_flag_and_the_password_never_appear_in_the_output(tmp_path):
    steps = [step(1, tool_input={"command": f"curl -d {PASSWORD} t"}, output_sent_to_model=f"user {PASSWORD}"),
             step(2, tool_name="submit_flag", tool_input={"flag": FLAG}, output_sent_to_model=None, output_full=None),
             step(3, assistant_text=f"I found {FLAG}")]
    run_dir = make_run(tmp_path, steps, [event(1, 2, executed_sql=f"SELECT '{PASSWORD}'", sql_error=f"bad {FLAG}")])
    text = view.render(run_dir, show_score=True)
    assert FLAG not in text and PASSWORD not in text
    assert view.PASSWORD_MARK in text and view.FLAG_MARK in text


def test_the_condition_and_the_hint_are_hidden_and_the_score_only_with_the_flag(tmp_path):
    run_dir = make_run(tmp_path, [step(1)], [], with_score=True)
    default = view.render(run_dir)
    assert "SECRETHINTTEXT" not in default and "pass=" not in default and "SCORER (looked at last)" not in default
    shown = view.render(run_dir, show_score=True)
    assert "pass=False" in shown
    assert shown.index("LABEL LANGUAGE") < shown.index("SCORER (looked at last)")     # the score comes last


def test_show_score_says_so_when_there_is_no_score_json(tmp_path):
    run_dir = make_run(tmp_path, [step(1)], [])
    assert "no score.json" in view.render(run_dir, show_score=True)


# --- the causal-rule aids ------------------------------------------------------------------------


def test_the_first_appearance_of_the_password_and_the_flag_is_marked_on_that_step(tmp_path):
    steps = [step(1), step(2, output_sent_to_model=f"row {PASSWORD}"), step(3, output_sent_to_model=f"{PASSWORD} {FLAG}")]
    text = view.render(make_run(tmp_path, steps, []))
    assert text.count("FIRST appearance of the PASSWORD") == 1
    assert "password: first reached the model at step 2" in text
    assert "flag: first reached the model at step 3" in text
    assert text.index("FIRST appearance of the PASSWORD") < text.index("-- step 3")


def test_a_secret_hidden_by_truncation_is_reported_as_never_having_reached_the_model(tmp_path):
    steps = [step(1, output_full=f"... {FLAG}", output_sent_to_model="... cut", truncated=True)]
    text = view.render(make_run(tmp_path, steps, []))
    assert "flag: NEVER reached the model whole" in text and "truncation hid it" in text


def test_a_hallucinated_submission_is_reported_as_never_having_appeared(tmp_path):
    steps = [step(1), step(2, tool_name="submit_flag", tool_input={"flag": "FLAG-made-up"}, output_sent_to_model=None)]
    text = view.render(make_run(tmp_path, steps, []))
    assert "is NOT the run's flag" in text and "had NOT appeared in an earlier output" in text
    assert "FLAG-made-up" in text           # an invented string is not a secret


def test_a_submission_that_had_appeared_earlier_is_reported_so(tmp_path):
    steps = [step(1, output_sent_to_model="a leaked FLAG-seen-before here"),
             step(2, tool_name="submit_flag", tool_input={"flag": "FLAG-seen-before"}, output_sent_to_model=None)]
    assert "HAD appeared in an earlier output" in view.render(make_run(tmp_path, steps, []))


def test_submission_facts_with_no_submit_flag_call_is_none_and_the_text_says_so(tmp_path):
    run_dir = make_run(tmp_path, [step(1)], [])
    manifest, steps, _ = view.telemetry.load_run(run_dir)
    assert view.submission_facts(manifest, steps) is None
    assert "submit_flag: never called" in view.render(run_dir)


# --- target events under steps -------------------------------------------------------------------


def test_events_are_shown_under_the_step_whose_window_holds_them(tmp_path):
    steps = [step(1), step(2)]                                     # windows 2s-3s and 4s-5s
    events = [event(1, 2, 500, input_used="1'", executed_sql="SELECT x", rows_returned=0),
              event(2, 4, 500, path="/login", login_attempt=True, login_username="admin", login_success=False)]
    text = view.render(make_run(tmp_path, steps, events))
    first, second = text.index("-- step 1"), text.index("-- step 2")
    assert first < text.index("#1 GET /catalog") < second < text.index("#2 GET /login")
    assert "login 'admin' success=False" in text


def test_an_event_outside_every_window_is_listed_apart(tmp_path):
    text = view.render(make_run(tmp_path, [step(1)], [event(1, 30)]))
    assert "outside every step's window (1)" in text and "#1 GET /catalog" in text


def test_the_clock_offset_is_applied_before_matching(tmp_path):
    run_dir = make_run(tmp_path, [step(1)], [event(1, 12, 500)])           # raw time 12.5 s, step window 2-3 s
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    manifest["clock_offset_ms"] = 10000                                     # the container clock is 10 s ahead
    (run_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    text = view.render(run_dir)
    assert "outside every step's window" not in text


def test_the_creds_and_flag_flags_on_an_event_are_loud(tmp_path):
    text = view.render(make_run(tmp_path, [step(1)], [event(1, 2, response_contained_creds=True,
                                                            response_contained_flag=True, session_user="admin")]))
    assert "RESPONSE_HAS_CREDS" in text and "RESPONSE_HAS_FLAG" in text and "session_user=admin" in text


# --- steps that are not the model's words, clipping, ranges --------------------------------------


def test_a_platform_block_is_marked_as_not_the_models_words(tmp_path):
    steps = [step(1, tool_name=None, tool_input=None, stop_reason="content_filtered",
                  assistant_text="blocked by our content filters", output_sent_to_model=None, output_full=None)]
    text = view.render(make_run(tmp_path, steps, []))
    assert "provider_block" in text and "NOT the model's words" in text


def test_a_malformed_call_shows_its_error(tmp_path):
    steps = [step(1, tool_name=None, tool_input=None, tool_call_error="invalid_arguments",
                  raw_tool_use={"name": "run_command"}, output_sent_to_model=None, output_full=None)]
    text = view.render(make_run(tmp_path, steps, []))
    assert "malformed" in text and "invalid_arguments" in text


def test_clip_keeps_the_head_and_the_tail_and_says_how_much_it_cut():
    text = "H" * 100 + "M" * 1000 + "T" * 100
    clipped = view.clip(text, 300)
    assert clipped.startswith("H" * 100) and clipped.endswith("T" * 100)
    assert "characters cut from the middle" in clipped and len(clipped) < len(text)
    assert view.clip(text, None) == text
    assert view.clip("short", 300) == "short"


def test_a_long_output_is_clipped_by_default_and_whole_with_no_limit(tmp_path):
    body = "start " + "x" * 5000 + " the-end"
    run_dir = make_run(tmp_path, [step(1, output_sent_to_model=body, output_full=body)], [])
    assert "the-end" in view.render(run_dir) and "cut from the middle" in view.render(run_dir)
    assert "cut from the middle" not in view.render(run_dir, limit=None)


def test_steps_range_limits_which_steps_print(tmp_path):
    text = view.render(make_run(tmp_path, [step(1), step(2), step(3)], []), steps_range=(2, 2))
    assert "-- step 2" in text and "-- step 1 " not in text and "-- step 3 " not in text
    assert view.parse_range("5-9") == (5, 9) and view.parse_range("4") == (4, 4) and view.parse_range(None) is None


# --- finding a run -------------------------------------------------------------------------------


def test_resolve_run_takes_a_path_or_a_unique_id_prefix(tmp_path):
    a = make_run(tmp_path, [step(1)], [], run_id="aa" * 16)
    make_run(tmp_path, [step(1)], [], run_id="ab" * 16)
    assert view.resolve_run(str(a), tmp_path) == a
    assert view.resolve_run("aaaa", tmp_path) == a
    with pytest.raises(ValueError, match="matches 2"):
        view.resolve_run("a", tmp_path)                                     # ambiguous
    with pytest.raises(ValueError, match="matches 0"):
        view.resolve_run("ff", tmp_path)


def test_next_unlabeled_finds_the_first_row_with_no_label(tmp_path):
    path = tmp_path / "s.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=sheet.COLUMNS)
        writer.writeheader()
        writer.writerow({"run_id": "1" * 32, "outcome_label": "NO_PROGRESS", "detail": "gave_up",
                         "scorer_agreement": "agree", "key_evidence": "step 1"})
        writer.writerow({"run_id": "2" * 32, "definition_notes": "just a note"})        # a note alone is not a label
        writer.writerow({"run_id": "3" * 32})
    assert view.next_unlabeled(path) == "2" * 32


def test_next_unlabeled_says_when_everything_is_labeled(tmp_path):
    path = tmp_path / "s.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=sheet.COLUMNS)
        writer.writeheader()
        writer.writerow({"run_id": "1" * 32, "outcome_label": "NO_PROGRESS", "detail": "gave_up",
                         "scorer_agreement": "agree", "key_evidence": "step 1"})
    with pytest.raises(ValueError, match="already has a label"):
        view.next_unlabeled(path)


# --- the CLI -------------------------------------------------------------------------------------


def test_main_prints_a_run_and_the_legend(tmp_path, capsys):
    make_run(tmp_path, [step(1)], [])
    assert view.main([RUN_ID[:6], "--runs-dir", str(tmp_path)]) == 0
    assert "LABEL LANGUAGE" in capsys.readouterr().out
    assert view.main(["--legend"]) == 0
    assert "outcome_label - checked in this order" in capsys.readouterr().out


def test_main_exits_two_for_an_unknown_run(tmp_path, capsys):
    assert view.main(["nothing", "--runs-dir", str(tmp_path)]) == 2
    assert "matches 0" in capsys.readouterr().out
