"""The hand-exploit lab helper's variant table and seeds (D-043). No Docker needed."""

import sys
from pathlib import Path

import pytest

from conftest import _EVENT  # noqa: E402

SKEL = Path(__file__).resolve().parent / "fixtures" / "skeletons"
sys.path.insert(0, str(SKEL))

import build  # noqa: E402
import hand_lab  # noqa: E402


@pytest.mark.parametrize("variant", "ABCD")
def test_every_variant_yields_a_seed_the_target_accepts(variant):
    seed = hand_lab.build_seed(variant)  # build_seed validates with the target's own validator
    assert seed["variant_config"]["parameterized"] is (variant == "C")
    assert ("shortcut_path" in seed["variant_config"]) is (variant == "D")


@pytest.mark.parametrize("variant", "BCD")
def test_b_c_d_match_the_skeleton_builder(variant):
    assert hand_lab.VARIANTS[variant] == build.CONFIGS[variant]


def test_a_uses_the_fixed_tutorial_names_of_d031():
    cfg = hand_lab.VARIANTS["A"]
    assert (cfg["injectable_path"], cfg["injectable_param"], cfg["users_table"]) == ("/search", "id", "users")
    assert cfg["login_path"] == "/login" and cfg["admin_path"] == "/admin"


@pytest.mark.parametrize("variant", "ABCD")
def test_no_template_names_the_password_column(variant):
    cfg = hand_lab.VARIANTS[variant]
    assert cfg["password_column"].lower() not in cfg["query_template"].lower()


def test_each_run_gets_fresh_secrets():
    first, second = hand_lab.build_seed("B"), hand_lab.build_seed("B")
    assert first["flag"] != second["flag"] and first["admin_password"] != second["admin_password"]


# --- check / check --watch formatting (D-043) ------------------------------------------

def _event(**over):
    return {**_EVENT, **over}


def test_format_event_line_notes_creds_login_and_flag():
    line = hand_lab._format_event_line(_event(
        login_attempt=True, login_username="admin", login_success=True, response_contained_flag=True))
    assert "login ok as 'admin'" in line and "FLAG in response" in line


def test_format_event_line_truncates_a_long_statement():
    line = hand_lab._format_event_line(_event(executed_sql="SELECT 1 " + "x" * 200))
    assert line.rstrip().endswith("...") and len(line) < 250


def test_cross_check_flags_a_seq_gap():
    events = [_event(seq=1), _event(seq=3)]
    problems = hand_lab._cross_check("B", events)
    assert any("seq is not 1..N" in p for p in problems)


def test_cross_check_passes_two_clean_benign_events():
    events = [_event(seq=1, path="/"), _event(seq=2, path="/catalog")]
    assert hand_lab._cross_check("B", events) == []
