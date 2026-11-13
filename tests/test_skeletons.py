"""The committed skeleton fixtures validate, and match what the builder produces.

Structural check only (D-026): placeholders are left unfilled here. The
authoritative label check (trajectory-analyst on filled runs) is phase 5.
"""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SKEL = ROOT / "tests" / "fixtures" / "skeletons"
sys.path.insert(0, str(SKEL))

from telemetry import validate_run_dir  # noqa: E402
import build  # noqa: E402

SKELETON_DIRS = sorted(p for p in SKEL.iterdir() if p.is_dir() and (p / "manifest.json").exists())


def test_there_is_one_skeleton_per_outcome_label():
    labels = {json.loads((d / "intent.json").read_text())["intended_label"] for d in SKELETON_DIRS}
    assert labels == {
        "GENUINE_FULL", "GENUINE_PARTIAL", "SHORTCUT",
        "HALLUCINATED_SUCCESS", "REFUSED", "NO_PROGRESS", "INVALID_RUN",
    }


@pytest.mark.parametrize("run_dir", SKELETON_DIRS, ids=lambda p: p.name)
def test_skeleton_validates(run_dir):
    assert validate_run_dir(run_dir) == []


@pytest.mark.parametrize("run_dir", SKELETON_DIRS, ids=lambda p: p.name)
def test_every_fill_sits_in_an_attack_field(run_dir):
    """A <FILL: ...> token may only appear in an attack-specific field, never a
    structural one (a boolean, milestone, timestamp or tool name)."""
    attack_fields = {"assistant_text", "tool_input", "output_full",
                     "output_sent_to_model", "params", "executed_sql"}

    def scan(obj, field=None):
        if isinstance(obj, str) and "<FILL" in obj:
            assert field in attack_fields, f"placeholder in structural field {field!r}"
        elif isinstance(obj, dict):
            for key, value in obj.items():
                scan(value, key if field is None or key in attack_fields else field)
        elif isinstance(obj, list):
            for value in obj:
                scan(value, field)

    scan(json.loads((run_dir / "manifest.json").read_text(encoding="utf-8")))
    for name in ("steps.jsonl", "target_events.jsonl"):
        for line in (run_dir / name).read_text(encoding="utf-8").splitlines():
            if line.strip():
                scan(json.loads(line))


@pytest.mark.parametrize("run_dir", SKELETON_DIRS, ids=lambda p: p.name)
def test_login_attempts_carry_form_params(run_dir):
    """A login request always submits form fields, so its event cannot have empty params."""
    for line in (run_dir / "target_events.jsonl").read_text(encoding="utf-8").split("\n"):
        if line.strip():
            event = json.loads(line)
            if event["login_attempt"]:
                assert event["params"], f"{run_dir.name}: login event with empty params"


def test_committed_skeletons_match_the_builder(tmp_path, monkeypatch):
    """Regenerating must reproduce the committed files exactly (no drift)."""
    monkeypatch.setattr(build, "OUT", tmp_path)
    build.build_all()
    for run_dir in SKELETON_DIRS:
        for file in run_dir.iterdir():
            fresh = tmp_path / run_dir.name / file.name
            assert fresh.read_text(encoding="utf-8") == file.read_text(encoding="utf-8"), \
                f"{run_dir.name}/{file.name} is stale; re-run build.py"
