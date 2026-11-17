"""execute_run against REAL Docker with a scripted model (PLAN.md phase 4, build step 4).

Everything but the model is real: the compose stack, the preflight, seeding, `docker exec`, the target's own
event log, the end-of-run order, teardown, the validator and the scorer. The scripted model only fetches two
harmless pages and submits a wrong flag, so this costs nothing and contains no attack content. Skipped without
Docker or the built images (see tests/test_lab_docker.py).
"""

import json
import re
import uuid
from datetime import datetime, timezone

import pytest
from harness_fakes import FakeClock, FakeModel, command, submit
from lab import Lab
from prompt_set import load_prompts
from run import UNKNOWN_DIGEST, execute_run
from scorer import score_run_dir
from telemetry import clock_drift_ms, validate_run_dir
from test_lab_docker import _docker_ready

pytestmark = pytest.mark.skipif(not _docker_ready(), reason="needs Docker and the built lab images (run.py build)")

COMMIT = "b" * 40
SCRIPT = [
    command("curl -s -o /dev/null -w '%{http_code}\\n' http://target:8080/"),
    command("curl -s -o /dev/null -w '%{http_code}\\n' http://target:8080/nothing-here"),
    submit("not-the-flag-just-a-guess-for-the-test"),
]


def real_clock() -> datetime:
    return datetime.now(timezone.utc)


@pytest.mark.parametrize("variant", ["A", "B", "C", "D"])
def test_a_scripted_run_against_the_real_lab_leaves_a_valid_scored_record(tmp_path, variant):
    lab = Lab(variant, uuid.uuid4().hex)
    model = FakeModel(list(SCRIPT), FakeClock())
    run_dir = execute_run(
        variant=variant, condition="no_hint", lab=lab, model=model, prompts=load_prompts(), runs_dir=tmp_path,
        clock=real_clock, harness_commit=COMMIT, order_seed=1, score_fn=lambda d: score_run_dir(d, COMMIT))
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    notes = json.loads((run_dir / "harness_notes.json").read_text(encoding="utf-8"))
    events = [json.loads(line) for line in (run_dir / "target_events.jsonl").read_text(encoding="utf-8").splitlines()]
    steps = [json.loads(line) for line in (run_dir / "steps.jsonl").read_text(encoding="utf-8").splitlines()]

    # The directory is valid as a whole, with the score in it, and nothing went wrong.
    assert validate_run_dir(run_dir) == [] and notes["validation"] == []
    assert manifest["termination_reason"] == "submitted" and manifest["harness_error"] is None
    assert [s["tool_name"] for s in steps] == ["run_command", "run_command", "submit_flag"]
    assert [s["output_sent_to_model"] for s in steps[:2]] == ["200\n", "404\n"]

    # The target log holds exactly the two requests the agent made: the health probes are TCP only.
    assert [(e["path"], e["status"]) for e in events] == [("/", 200), ("/nothing-here", 404)]
    assert [e["seq"] for e in events] == [1, 2]

    # The clock: measured at the start and again at the end, small, and no drift flagged.
    assert abs(manifest["clock_offset_ms"]) < 250 and manifest["clock_offset_end_ms"] is not None
    assert clock_drift_ms(manifest) is None

    # What ran is recorded, and it was not a placeholder.
    assert all(re.fullmatch(r"sha256:[0-9a-f]{64}", d) and d != UNKNOWN_DIGEST for d in manifest["image_digests"].values())
    assert manifest["container_exit_codes"]["target"] is None and isinstance(manifest["container_exit_codes"]["attacker"], int)
    assert manifest["target_health_start"] == manifest["target_health_end"] == "healthy"

    # The score: a wrong guess with no injection is a fail at the first milestone.
    score = json.loads((run_dir / "score.json").read_text(encoding="utf-8"))
    assert (score["flag_submitted"], score["flag_correct"], score["pass"], score["milestones"]) == (True, False, False, [])

    # The stack is gone, nothing leaked into the files an analysis reads, and no partial record is left.
    assert not any(lab.leftovers(lab.project).values()) and notes["left_after_down"] == []
    for name in ("steps.jsonl", "target_events.jsonl", "harness_notes.json"):
        text = (run_dir / name).read_text(encoding="utf-8")
        assert manifest["flag"] not in text and manifest["admin_password"] not in text, name
    assert not (run_dir / "manifest.partial.json").exists()
    assert notes["preflight"]["isolated"] is True and notes["fresh_state"]["users"] == 5


def test_a_second_run_starts_from_a_verified_clean_state(tmp_path):
    first = execute_run(variant="B", condition="no_hint", lab=Lab("B", uuid.uuid4().hex), model=FakeModel(list(SCRIPT), FakeClock()),
                        prompts=load_prompts(), runs_dir=tmp_path, clock=real_clock, harness_commit=COMMIT)
    second_lab = Lab("B", uuid.uuid4().hex)
    # Before the second run's `up`: nothing of the first is left (PLAN.md phase 4 done-when).
    assert not any(second_lab.leftovers().values())
    second = execute_run(variant="B", condition="hint", lab=second_lab, model=FakeModel(list(SCRIPT), FakeClock()),
                         prompts=load_prompts(), runs_dir=tmp_path, clock=real_clock, harness_commit=COMMIT)
    notes = json.loads((second / "harness_notes.json").read_text(encoding="utf-8"))
    assert notes["fresh_state"] == {"items": 6, "users": 5, "admin": "admin"} and notes["swept"] == {"containers": 0, "networks": 0, "volumes": 0}
    assert validate_run_dir(first, include_score=False) == [] and validate_run_dir(second, include_score=False) == []
    # Event numbering restarted at 1 in a fresh target, so nothing carried over from the first run.
    assert json.loads((second / "target_events.jsonl").read_text(encoding="utf-8").splitlines()[0])["seq"] == 1
