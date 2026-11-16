"""fill_locally.py: what it fills, what it reports as unfillable, and that it never
touches structural fields (D-044). No Docker; synthetic "real" events use harmless,
neutral values (reusing build.event(), the same generator every committed skeleton is
built from), never anything resembling an actual attack payload.
"""

import json
import sys
from pathlib import Path

import pytest

SKEL = Path(__file__).resolve().parent / "fixtures" / "skeletons"
sys.path.insert(0, str(SKEL))

import build  # noqa: E402
import fill_locally as fl  # noqa: E402

RUN_ID = "a" * 32


def genuine_full():
    return fl.load_skeleton(SKEL / "genuine_full")


def no_progress_patched_c():
    return fl.load_skeleton(SKEL / "no_progress_patched_c")


def fully_filled_genuine_full():
    """genuine_full with all three fillable positions (2, 3, 4) applied, from harmless
    synthetic "real" events -- the shared setup for the cross-check and --path tests."""
    rec = genuine_full()
    probe = build.event(RUN_ID, 2, path="/catalog", sql="SELECT sku, label FROM stock WHERE label = 'sample-a'",
                        sql_error="syntax error", rows=None)
    probe["input_used"], probe["params"], probe["seq"] = "sample-a", {"ref": "sample-a"}, 7
    extract = build.event(RUN_ID, 3, path="/catalog", sql="SELECT sku, label FROM stock WHERE label = 'sample-b'",
                          rows=1, creds=True)
    extract["input_used"], extract["params"], extract["seq"] = "sample-b", {"ref": "sample-b"}, 9
    login = build.event(RUN_ID, 4, method="POST", path="/login", login=True,
                        login_user="admin", login_ok=True, user="admin")
    login["params"], login["seq"] = {"username": "admin", "password": "sample-password"}, 12
    fl.apply_fill(rec, {7: probe, 9: extract, 12: login}, {2: 7, 3: 9, 4: 12})
    return rec


# --- find_fills ------------------------------------------------------------------------

def test_find_fills_reports_a_dotted_and_indexed_path():
    obj = {"a": [{"b": "<FILL: x>"}, {"b": "concrete"}]}
    found = fl.find_fills(obj)
    assert found == [("a[0].b", "<FILL: x>")]


def test_find_fills_ignores_strings_that_only_resemble_a_fill():
    assert fl.find_fills({"a": "<FILLED IN>", "b": "no fill here"}) == []


# --- gaps on the real genuine_full skeleton -------------------------------------------

def test_gaps_on_genuine_full_matches_known_positions():
    rec = genuine_full()
    lines = fl.describe_gaps(rec)
    assert "event positions apply can fill: [2, 3, 4]" in lines


def test_gaps_separates_unfillable_step_content_from_fillable_events():
    rec = genuine_full()
    text = "\n".join(fl.describe_gaps(rec))
    assert "hand_lab never records your typed commands" in text
    assert "the agent's own reasoning" in text
    assert "apply --map" in text


def test_every_committed_skeleton_has_no_gaps_outside_known_categories():
    # Every skeleton either has nothing left, or only the three known-unfillable kinds
    # of step content plus fillable events -- never some fourth, unrecognized gap.
    step_markers = (".tool_input", ".assistant_text", ".output_full", ".output_sent_to_model")
    for name in fl.list_skeletons():
        rec = fl.load_skeleton(SKEL / name)
        for path, _ in fl.find_fills(rec):
            is_step = path.startswith("steps[") and any(marker in path for marker in step_markers)
            is_event = path.startswith("events[")
            assert is_step or is_event, f"{name}: unexpected gap at {path}"


# --- apply_fill: the three fields it's allowed to touch -------------------------------

def test_apply_fills_a_search_event_without_touching_structural_fields():
    rec = genuine_full()
    before = dict(rec["events"][1])  # position 2: the probe event

    real = build.event(RUN_ID, 1, path="/catalog", sql="SELECT sku, label FROM stock WHERE label = 'sample-value'",
                        sql_error=None, rows=0)
    real["input_used"] = "sample-value"
    real["params"] = {"ref": "sample-value"}
    real["seq"] = 7

    notes = fl.apply_fill(rec, {7: real}, {2: 7})
    after = rec["events"][1]

    assert after["input_used"] == "sample-value" and after["params"] == {"ref": "sample-value"}
    assert after["executed_sql"] == "SELECT sku, label FROM stock WHERE label = 'sample-value'"
    # Structural fields the skeleton's own story depends on are untouched.
    for field in ("sql_error", "rows_returned", "response_contained_creds", "status", "method", "path"):
        assert after[field] == before[field], field
    assert any("event 2" in n for n in notes)


def test_apply_fills_sql_params_on_a_bound_variant():
    # Caught by running gaps --all myself: render_bound puts the placeholder inside
    # sql_params too on a parameterized variant (C), which the search-event branch
    # didn't copy. no_progress_patched_c is the one committed skeleton that's bound.
    rec = no_progress_patched_c()
    real = build.event(RUN_ID, 1, path="/catalog", bound=True, rows=0, creds=False)
    real["executed_sql"], real["sql_params"] = build.render_bound(build.CONFIG["query_template"], "sample-c")
    real["input_used"], real["params"], real["seq"] = "sample-c", {"ref": "sample-c"}, 5

    notes = fl.apply_fill(rec, {5: real}, {1: 5})

    assert rec["events"][0]["sql_params"] == ["sample-c"]
    assert any("sql_params filled" in n for n in notes)
    assert fl.validate_filled(rec) == []


def test_apply_leaves_sql_params_alone_on_an_unbound_variant():
    # Harmless no-op on B/D: the real event's sql_params is already [].
    rec = genuine_full()
    before = list(rec["events"][1]["sql_params"])
    real = build.event(RUN_ID, 2, path="/catalog", sql="x", rows=0)
    real["seq"] = 7
    fl.apply_fill(rec, {7: real}, {2: 7})
    assert rec["events"][1]["sql_params"] == before == []


def test_apply_fills_a_login_event_matching_the_real_shape():
    # build.py's own login events are flat ({"username", "password"}), matching the
    # real app (events.py) -- no mismatch note, since there's nothing to flag.
    rec = genuine_full()
    real = build.event(RUN_ID, 4, method="POST", path="/login", login=True,
                        login_user="admin", login_ok=True, user="admin")
    real["params"] = {"username": "admin", "password": "sample-password-value"}
    real["seq"] = 12

    notes = fl.apply_fill(rec, {12: real}, {4: 12})

    assert rec["events"][3]["params"] == {"username": "admin", "password": "sample-password-value"}
    assert not any("shape changed" in n for n in notes)


def test_apply_flags_a_login_shape_mismatch_when_one_exists():
    # The detection itself, independent of whether build.py currently has a bug: force
    # a skeleton event back into the old (wrong) {"form": ...} shape and confirm apply
    # still notices a real one doesn't match it.
    rec = genuine_full()
    rec["events"][3]["params"] = {"form": "<FILL: the submitted login form fields>"}
    real = build.event(RUN_ID, 4, method="POST", path="/login", login=True,
                        login_user="admin", login_ok=True, user="admin")
    real["params"] = {"username": "admin", "password": "sample-password-value"}
    real["seq"] = 12

    notes = fl.apply_fill(rec, {12: real}, {4: 12})

    assert rec["events"][3]["params"] == {"username": "admin", "password": "sample-password-value"}
    assert any("shape changed" in n for n in notes)


def test_apply_does_not_touch_the_admin_or_homepage_events():
    rec = genuine_full()
    homepage_before, admin_before = dict(rec["events"][0]), dict(rec["events"][4])
    real = build.event(RUN_ID, 2, path="/catalog", sql="x", rows=0)
    real["seq"] = 7
    fl.apply_fill(rec, {7: real}, {2: 7})
    assert rec["events"][0] == homepage_before and rec["events"][4] == admin_before


# --- apply_fill: error handling --------------------------------------------------------

def test_apply_rejects_an_out_of_range_position():
    rec = genuine_full()
    with pytest.raises(ValueError, match="out of range"):
        fl.apply_fill(rec, {7: build.event(RUN_ID, 1)}, {99: 7})


def test_apply_rejects_a_missing_real_seq():
    rec = genuine_full()
    with pytest.raises(ValueError, match="no event with seq"):
        fl.apply_fill(rec, {7: build.event(RUN_ID, 1)}, {2: 404})


def test_apply_rejects_mapping_the_admin_event():
    rec = genuine_full()
    real = build.event(RUN_ID, 5, path="/admin", flag=True, user="admin")
    real["seq"] = 7
    with pytest.raises(ValueError, match="neither the injectable nor the login path"):
        fl.apply_fill(rec, {7: real}, {5: 7})


# --- round trip and the post-fill cross-check ------------------------------------------

def test_write_then_load_round_trips(tmp_path):
    rec = genuine_full()
    fl.write_skeleton(tmp_path / "out", rec)
    assert fl.load_skeleton(tmp_path / "out") == rec


def test_a_consistent_fill_leaves_no_cross_check_problems(tmp_path):
    rec = fully_filled_genuine_full()
    fl.write_skeleton(tmp_path / "out", rec)

    assert fl.validate_filled(rec) == []
    remaining = fl.describe_gaps(rec)
    assert "event positions apply can fill" not in "\n".join(remaining)  # all three events are now done


# --- gaps --path: inspecting a filled copy instead of the committed skeleton -----------

def test_gaps_defaults_to_the_committed_skeleton(capsys):
    fl.cmd_gaps("genuine_full", None)
    assert "event positions apply can fill: [2, 3, 4]" in capsys.readouterr().out


def test_gaps_path_reads_a_filled_copy_instead(tmp_path, capsys):
    out_dir = tmp_path / "filled_copy"
    fl.write_skeleton(out_dir, fully_filled_genuine_full())

    fl.cmd_gaps(None, out_dir)
    out = capsys.readouterr().out
    assert "event positions apply can fill" not in out  # all three events are already filled
    assert "the agent's own reasoning" in out  # step-level gaps are unaffected by --path


def test_gaps_rejects_an_unknown_committed_name():
    with pytest.raises(SystemExit, match="no such committed skeleton"):
        fl.cmd_gaps("not-a-real-skeleton", None)


def test_gaps_requires_a_name_or_a_path():
    with pytest.raises(SystemExit, match="needs a skeleton name"):
        fl.cmd_gaps(None, None)


# --- describe_gaps sections: --targets / --steps ---------------------------------------

def test_describe_gaps_targets_only_omits_step_content():
    text = "\n".join(fl.describe_gaps(genuine_full(), sections={"events"}))
    assert "fillable: apply --map" in text
    assert "agent's own reasoning" not in text and "steps.jsonl" not in text


def test_describe_gaps_steps_only_omits_event_content():
    text = "\n".join(fl.describe_gaps(genuine_full(), sections={"steps"}))
    assert "agent's own reasoning" in text
    assert "fillable: apply --map" not in text and "target_events.jsonl" not in text


# --- gaps --all: every committed skeleton in one report --------------------------------

def test_gaps_all_reports_every_committed_skeleton(capsys):
    fl.cmd_gaps(None, None, show_all=True)
    out = capsys.readouterr().out
    for skeleton_name in fl.list_skeletons():
        assert f"{skeleton_name}:" in out


def test_gaps_all_rejects_a_name_or_path():
    with pytest.raises(SystemExit, match="can't be combined"):
        fl.cmd_gaps("genuine_full", None, show_all=True)
    with pytest.raises(SystemExit, match="can't be combined"):
        fl.cmd_gaps(None, Path("somewhere"), show_all=True)


def test_gaps_all_respects_the_section_filter(capsys):
    fl.cmd_gaps(None, None, show_all=True, sections={"targets_impossible_sentinel"})
    out = capsys.readouterr().out
    # No skeleton has a "manifest"/"intent"/"score" gap, so an unmatched section name
    # should report every skeleton as fully clean -- confirms the filter is actually
    # applied across --all, not just ignored.
    assert "nothing left -- every placeholder is filled" in out
    assert "fillable: apply --map" not in out and "agent's own reasoning" not in out
