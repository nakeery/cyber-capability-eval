"""execute_run against a fake lab, a fake model and one shared clock (PLAN.md phase 4, build step 4).

The real Docker lifecycle is covered by tests/test_lab.py (argv and parsing, against a fake runner) and
tests/test_lab_docker.py (the real thing, skipped without Docker). Here the question is what run.py does
with the answers: the order of the end of a run, what the manifest says when something fails, and that the
directory it leaves validates.
"""

import dataclasses
import functools
import json
import re
import shutil
import subprocess
from datetime import datetime, timezone

import pytest
from agent import INFERENCE_CONFIG, Limits
from harness_fakes import BEDROCK_INFERENCE, FakeClock, FakeExecutor, FakeModel, command, outcome, submit, text_reply
from lab import HarnessError
from model import ModelError
from outcome import load_outcome
from prompt_set import load_prompts
from run import (UNKNOWN_DIGEST, default_score, find_orphans, git_provenance, new_seed, run_lock, summarize)
from run import execute_run as _execute_run

# Every FakeModel in this file is labeled backend "bedrock", and the production temperature (D-084) is above what a
# Bedrock manifest may record (schemas/run_manifest.schema.json). So a run of one records a Bedrock-legal config;
# the local-model helper below passes the production INFERENCE_CONFIG explicitly.
execute_run = functools.partial(_execute_run, inference=BEDROCK_INFERENCE)
from telemetry import validate_record, validate_run_dir
from variant_registry import VARIANTS

PROMPTS = load_prompts()
RUN_ID = "0123456789abcdef0123456789abcdef"
COMMIT = "b" * 40


class FakeLab:
    """Stands in for lab.Lab: records the order of calls and advances the shared clock like Docker would."""

    def __init__(self, clock, *, events=(), fail_at=None, offsets=((0.0, 5.0), (0.0, 5.0)), left_after_down=(),
                 healthy=True, run_dir=None):
        self.clock, self.events, self.fail_at, self.offsets = clock, list(events), fail_at, list(offsets)
        self.left_after_down, self.healthy, self.run_dir = list(left_after_down), healthy, run_dir
        self.run_id, self.attacker, self.target, self.calls, self.seen_seed = RUN_ID, "lab-x-attacker-1", "lab-x-target-1", [], None
        self.partial_existed_at_up = None
        self.attacker_alive = True
        self.attacker_facts = {"running": False, "oom_killed": False, "exit_code": 137, "finished_at": "2026-11-12T10:00:00Z"}
        self.fail_clock_after_first = False

    def _step(self, name):
        self.calls.append(name)
        if self.fail_at == name:
            raise HarnessError(f"{name} failed on purpose")

    def docker_version(self): self._step("docker_version"); return "29.9.2"
    def sweep(self): self._step("sweep"); return {"containers": 0, "networks": 0, "volumes": 0}
    def assert_clean(self): self._step("assert_clean")
    def check_disk(self): self._step("check_disk"); return 10 ** 10

    def up(self):
        self._step("up")
        self.partial_existed_at_up = (self.run_dir / RUN_ID / "manifest.partial.json").exists() if self.run_dir else None

    def image_digests(self): self._step("image_digests"); return {"attacker": "sha256:" + "a" * 64, "target": "sha256:" + "c" * 64}
    def preflight(self): self._step("preflight"); return {"gateway": "172.18.0.1"}
    def seed(self, seed): self._step("seed"); self.seen_seed = seed
    def wait_ready(self): self._step("wait_ready")
    def verify_fresh_state(self, seed): self._step("verify_fresh_state"); return {"items": 6, "users": 5}

    def measure_clock(self):
        self._step("measure_clock")
        if self.fail_clock_after_first and self.calls.count("measure_clock") > 1:
            raise HarnessError("could not read the target's clock: the container is not running")
        return self.offsets.pop(0) if len(self.offsets) > 1 else self.offsets[0]

    @staticmethod
    def check_offset(offset_ms):
        if abs(offset_ms) > 250:
            raise HarnessError(f"clock: the container clock is {offset_ms:.0f} ms from the host's, beyond the 250 ms limit")

    def health(self, attempts=1):
        self.calls.append("health")
        return self.healthy() if callable(self.healthy) else self.healthy

    def attacker_running(self):
        self.calls.append("attacker_running")
        return self.attacker_alive

    def attacker_state(self):
        self.calls.append("attacker_state")
        return dict(self.attacker_facts)

    def stop_attacker(self): self._step("stop_attacker"); self.clock.advance(2); return 143
    def target_exit_code(self): self._step("target_exit_code"); return None
    def stop_target(self): self._step("stop_target"); return 143

    def collect_events(self):
        self._step("collect_events")
        return list(self.events), {"events": len(self.events), "log_bytes": 0, "target_stderr_bytes": 0}

    def down(self): self._step("down"); return list(self.left_after_down)


def make(tmp_path, script, *, variant="B", condition="no_hint", lab_kwargs=None, results=None, seed=None, prompts=PROMPTS,
         score_fn=None, dirty=(), exec_seconds=0.0, latency=0.0, executor=None, limits=None):
    clock = FakeClock()
    lab = FakeLab(clock, run_dir=tmp_path, **(lab_kwargs or {}))
    model = FakeModel(script, clock, latency)
    model.region = "us-east-1"
    run_dir = execute_run(
        variant=variant, condition=condition, lab=lab, model=model, prompts=prompts, runs_dir=tmp_path, clock=clock,
        harness_commit=COMMIT, dirty_paths=list(dirty), order_seed=7, seed=seed or new_seed(variant), score_fn=score_fn,
        executor_factory=lambda _lab: executor or FakeExecutor(clock, results, exec_seconds),
        # D-083's production default is 4; most of these tests use a bare text_reply() just to end the
        # script cleanly, written before the nudge existed. A test actually about it passes its own.
        limits=limits if limits is not None else Limits(text_only_limit=1), inference=BEDROCK_INFERENCE)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    notes = json.loads((run_dir / "harness_notes.json").read_text(encoding="utf-8"))
    steps = [json.loads(line) for line in (run_dir / "steps.jsonl").read_text(encoding="utf-8").splitlines() if line]
    return run_dir, manifest, notes, steps, lab, model


def index(calls, name, nth=0):
    return [i for i, call in enumerate(calls) if call == name][nth]


# --- a normal run ----------------------------------------------------------------------

def test_a_run_leaves_a_directory_that_validates(tmp_path):
    run_dir, manifest, notes, steps, lab, _ = make(tmp_path, [command("ls"), submit("a guess")])
    assert validate_run_dir(run_dir, include_score=False) == []
    assert notes["validation"] == []
    assert (manifest["termination_reason"], len(steps), manifest["harness_error"]) == ("submitted", 2, None)
    assert sorted(p.name for p in run_dir.iterdir()) == ["harness_notes.json", "manifest.json", "steps.jsonl", "target_events.jsonl"]


def test_the_manifest_schema_caps_temperature_for_a_bedrock_run_only(tmp_path):
    # D-084: the production temperature (1.2) is above Bedrock's 0-1 range. A Bedrock manifest (backend bedrock, or no
    # backend at all, as before D-060) must not claim it; a local run's manifest may.
    _, manifest, *_ = make(tmp_path, [text_reply()])
    hot = {**manifest, "inference_config": {**manifest["inference_config"], "temperature": 1.2}}
    assert any("temperature" in problem for problem in validate_record("manifest", hot))
    no_backend = {key: value for key, value in hot.items() if key != "backend"}
    assert any("temperature" in problem for problem in validate_record("manifest", no_backend))
    cold = {**manifest, "inference_config": {**manifest["inference_config"], "temperature": -0.1}}
    assert any("temperature" in problem for problem in validate_record("manifest", cold))


def test_a_local_run_records_the_production_sampling_and_validates(tmp_path):
    _, manifest, _, _, model = run_local(tmp_path, [text_reply()])
    assert manifest["backend"] == "local" and manifest["inference_config"] == INFERENCE_CONFIG
    assert model.requests[0]["inference"] == manifest["inference_config"]      # recorded = sent
    assert manifest["inference_config"]["temperature"] > 1
    assert validate_record("manifest", manifest) == []


def test_the_manifest_records_what_ran(tmp_path):
    seed = new_seed("B")
    run_dir, manifest, notes, steps, lab, model = make(tmp_path, [text_reply()], condition="hint", seed=seed)
    assert validate_record("manifest", manifest) == []
    # What the manifest says the sampling was is what the model was sent: both come from the one value execute_run
    # was given, and nothing else would notice if they drifted apart.
    assert model.requests[0]["inference"] == manifest["inference_config"]
    assert manifest["variant_config"] == VARIANTS["B"]["variant_config"] and manifest["variant"] == "B"
    assert (manifest["flag"], manifest["admin_password"]) == (seed["flag"], seed["admin_password"])
    assert manifest["system_prompt_hash"] == PROMPTS.system_prompt_hash("hint")
    assert manifest["hint_text"] == PROMPTS.hint and manifest["condition"] == "hint"
    assert (manifest["backend"], manifest["region"], manifest["model_id"]) == ("bedrock", "us-east-1", "fake-model")
    assert manifest["inference_config"] == BEDROCK_INFERENCE
    assert (manifest["step_cap"], manifest["harness_commit"], manifest["run_order_seed"]) == (30, COMMIT, 7)
    assert manifest["image_digests"] == {"attacker": "sha256:" + "a" * 64, "target": "sha256:" + "c" * 64}
    assert manifest["docker_version"] == "29.9.2" and manifest["target_health_start"] == "healthy"
    assert manifest["container_exit_codes"] == {"attacker": 143, "target": None}


@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_every_variants_run_validates_against_the_registry(tmp_path, variant):
    run_dir, manifest, *_ = make(tmp_path, [text_reply()], variant=variant)
    assert validate_run_dir(run_dir, include_score=False) == []
    assert ("shortcut_path" in manifest["variant_config"]) == (variant == "D")


def test_the_end_of_a_run_happens_in_the_order_the_decisions_require(tmp_path):
    *_, lab, _ = make(tmp_path, [command("ls"), submit()])
    calls = lab.calls
    order = ["sweep", "assert_clean", "up", "preflight", "seed", "wait_ready", "verify_fresh_state", "measure_clock"]
    assert [calls[calls.index(name)] for name in order] == order and [calls.index(n) for n in order] == sorted(calls.index(n) for n in order)
    # D-037: the attacker is stopped first, then the clock is measured again while the target still runs,
    # and only then is the target stopped and its log read; teardown is last.
    end = [index(calls, "stop_attacker"), index(calls, "measure_clock", 1), index(calls, "stop_target"),
           index(calls, "collect_events"), index(calls, "down")]
    assert end == sorted(end) and calls[-1] == "down"


def test_ended_at_is_after_the_attacker_was_stopped(tmp_path):
    # FakeLab.stop_attacker takes 2 s on the shared clock. ended_at must be after it (D-037), so
    # nothing the attacker left running can touch the target before the run is over.
    _, manifest, _, steps, *_ = make(tmp_path, [command("ls"), submit()])
    last_end = datetime.fromisoformat(steps[-1]["ended_at"])
    assert (datetime.fromisoformat(manifest["ended_at"]) - last_end).total_seconds() == 2


def test_the_window_starts_just_before_the_first_model_call(tmp_path):
    _, manifest, _, steps, *_ = make(tmp_path, [command("ls"), submit()], latency=3)
    assert manifest["started_at"] == "2026-11-12T10:00:00+00:00"
    assert steps[0]["started_at"] == "2026-11-12T10:00:03+00:00"      # the model call is outside the step


def test_one_clock_reads_both_the_steps_and_the_manifest(tmp_path):
    # PLAN.md dependency 5: step times and the manifest's times come from the same wall clock. The validator
    # checks every step lies inside the manifest's window; that only holds if both used one clock.
    run_dir, *_ = make(tmp_path, [command("a"), command("b"), submit()], latency=1.5, exec_seconds=4)
    assert validate_run_dir(run_dir, include_score=False) == []


def test_the_partial_manifest_exists_before_the_stack_comes_up_and_is_gone_after(tmp_path):
    run_dir, _, _, _, lab, _ = make(tmp_path, [text_reply()])
    assert lab.partial_existed_at_up is True
    assert not (run_dir / "manifest.partial.json").exists()


def test_the_partial_manifest_holds_the_secrets_a_killed_run_would_otherwise_lose(tmp_path):
    seed = new_seed("B")
    clock = FakeClock()

    class Dies(FakeLab):
        def up(self):
            raise SystemExit("killed")      # not an Exception: nothing in execute_run catches it

    with pytest.raises(SystemExit):
        execute_run(variant="B", condition="no_hint", lab=Dies(clock), model=FakeModel([], clock), prompts=PROMPTS,
                    runs_dir=tmp_path, clock=clock, harness_commit=COMMIT, seed=seed)
    partial = json.loads((tmp_path / RUN_ID / "manifest.partial.json").read_text(encoding="utf-8"))
    assert (partial["flag"], partial["admin_password"]) == (seed["flag"], seed["admin_password"])
    assert find_orphans(tmp_path) == [RUN_ID]


# --- secrets stay where they belong --------------------------------------------------------

def test_the_flag_and_password_appear_only_in_the_manifest(tmp_path):
    seed = new_seed("B")
    run_dir, *_ = make(tmp_path, [command("ls"), text_reply("done")], seed=seed)
    for name in ("steps.jsonl", "target_events.jsonl", "harness_notes.json"):
        text = (run_dir / name).read_text(encoding="utf-8")
        assert seed["flag"] not in text and seed["admin_password"] not in text and seed["secret_key"] not in text, name
    assert seed["flag"] in (run_dir / "manifest.json").read_text(encoding="utf-8")


def test_the_summary_shows_no_secret_and_no_agent_text(tmp_path):
    seed = new_seed("B")
    run_dir, *_ = make(tmp_path, [command("ls", text="MY PRIVATE REASONING"), submit()], seed=seed,
                       results=[outcome("OUTPUT FROM THE TARGET\n")])
    shown = summarize(run_dir)
    assert "submitted" in shown and "validation: ok" in shown
    assert not any(text in shown for text in (seed["flag"], seed["admin_password"], "MY PRIVATE REASONING", "OUTPUT FROM"))


# --- failures: every one still leaves a valid, countable record ----------------------------------

def test_a_preflight_failure_is_a_harness_error_with_no_model_call_and_a_valid_record(tmp_path):
    run_dir, manifest, notes, steps, lab, model = make(tmp_path, [text_reply()], lab_kwargs={"fail_at": "preflight"})
    assert manifest["termination_reason"] == "harness_error" and "preflight failed on purpose" in manifest["harness_error"]
    assert (steps, model.requests, (run_dir / "target_events.jsonl").read_text(encoding="utf-8")) == ([], [], "")
    assert validate_run_dir(run_dir, include_score=False) == []
    assert "down" in lab.calls                    # the stack is removed whatever happened
    assert datetime.fromisoformat(manifest["started_at"]) <= datetime.fromisoformat(manifest["ended_at"])


def test_a_failure_before_up_never_touches_the_stack_it_did_not_create(tmp_path):
    run_dir, manifest, _, _, lab, _ = make(tmp_path, [text_reply()], lab_kwargs={"fail_at": "assert_clean"})
    assert "up" not in lab.calls and "stop_attacker" not in lab.calls and "collect_events" not in lab.calls
    assert lab.calls[-1] == "down"
    assert manifest["image_digests"] == {"attacker": UNKNOWN_DIGEST, "target": UNKNOWN_DIGEST}
    assert validate_run_dir(run_dir, include_score=False) == []


def test_a_clock_offset_beyond_the_limit_ends_the_run_but_still_records_the_offset(tmp_path):
    run_dir, manifest, *_ = make(tmp_path, [text_reply()], lab_kwargs={"offsets": [(400.0, 8.0)]})
    assert manifest["termination_reason"] == "harness_error" and "250 ms" in manifest["harness_error"]
    assert (manifest["clock_offset_ms"], manifest["clock_uncertainty_ms"]) == (400.0, 8.0)
    assert validate_run_dir(run_dir, include_score=False) == []


def test_an_unhealthy_target_at_the_start_is_a_harness_error(tmp_path):
    _, manifest, _, _, _, model = make(tmp_path, [text_reply()], lab_kwargs={"healthy": False})
    assert manifest["termination_reason"] == "harness_error" and "not healthy" in manifest["harness_error"]
    assert model.requests == [] and manifest["target_health_start"] == "unknown" and manifest["target_health_end"] == "unhealthy"


def test_clock_drift_is_flagged_and_changes_nothing_else(tmp_path):
    run_dir, manifest, notes, *_ = make(tmp_path, [command("ls"), submit()], lab_kwargs={"offsets": [(0.0, 5.0), (500.0, 5.0)]})
    assert (manifest["clock_offset_ms"], manifest["clock_offset_end_ms"]) == (0.0, 500.0)
    assert manifest["termination_reason"] == "submitted"           # drift is a flag, not a termination (D-065)
    assert notes["clock_drift_ms"] == 500
    assert validate_run_dir(run_dir, include_score=False) == []
    assert "drifted 500 ms" in summarize(run_dir)


def test_a_failure_after_the_submission_still_validates_and_says_what_the_loop_did(tmp_path):
    run_dir, manifest, notes, steps, *_ = make(tmp_path, [submit("a guess")], lab_kwargs={"fail_at": "collect_events"})
    assert steps[-1]["tool_name"] == "submit_flag"
    assert manifest["termination_reason"] == "harness_error"
    assert "collect_events failed on purpose" in manifest["harness_error"] and "had ended as submitted" in manifest["harness_error"]
    assert validate_run_dir(run_dir, include_score=False) == []


def test_every_failing_end_step_is_kept_and_the_rest_still_run(tmp_path):
    class Flaky(FakeLab):
        def stop_attacker(self): self._step("stop_attacker"); raise HarnessError("the attacker would not stop")

    clock = FakeClock()
    lab = Flaky(clock, run_dir=tmp_path)
    run_dir = execute_run(variant="B", condition="no_hint", lab=lab, model=FakeModel([text_reply()], clock), prompts=PROMPTS,
                          runs_dir=tmp_path, clock=clock, harness_commit=COMMIT,
                          executor_factory=lambda _l: FakeExecutor(clock), limits=Limits(text_only_limit=1))
    notes = json.loads((run_dir / "harness_notes.json").read_text(encoding="utf-8"))
    assert any("would not stop" in p for p in notes["finish_problems"])
    assert {"stop_target", "collect_events", "down"} <= set(lab.calls)       # none of the rest was skipped


def test_an_api_error_is_not_a_harness_error_and_keeps_the_partial_record(tmp_path):
    first = dataclasses.replace(command("ls"), retries=1)
    run_dir, manifest, notes, steps, *_ = make(tmp_path, [first, ModelError("ThrottlingException: slow down", retries=4)])
    assert manifest["termination_reason"] == "api_error" and manifest["harness_error"] is None
    assert manifest["api_retries"] == 5 and len(steps) == 1
    assert "ThrottlingException" in notes["termination_detail"]
    assert validate_run_dir(run_dir, include_score=False) == []


def test_the_leak_invariant_ends_the_run_naming_the_secret_but_not_its_value(tmp_path):
    seed = new_seed("B")
    leaky = dataclasses.replace(PROMPTS, messages={**PROMPTS.messages, "timeout_notice": f"see {seed['flag']}"})
    run_dir, manifest, _, steps, _, model = make(tmp_path, [text_reply()], seed=seed, prompts=leaky)
    assert manifest["termination_reason"] == "harness_error" and "leak invariant" in manifest["harness_error"]
    assert seed["flag"] not in manifest["harness_error"] and steps == [] and model.requests == []


def test_an_unexpected_exception_is_recorded_and_the_stack_is_still_removed(tmp_path):
    class Boom:
        def run(self, text):
            raise RuntimeError("the executor broke")

    run_dir, manifest, notes, _, lab, _ = make(tmp_path, [command("ls")], executor=Boom())
    assert manifest["termination_reason"] == "harness_error" and "RuntimeError: the executor broke" in manifest["harness_error"]
    assert "RuntimeError" in notes["traceback"] and lab.calls[-1] == "down"
    assert validate_run_dir(run_dir, include_score=False) == []


def test_ctrl_c_still_writes_the_record_removes_the_stack_and_then_propagates(tmp_path):
    clock = FakeClock()
    lab = FakeLab(clock, run_dir=tmp_path)
    with pytest.raises(KeyboardInterrupt):
        execute_run(variant="B", condition="no_hint", lab=lab, model=FakeModel([KeyboardInterrupt()], clock),
                    prompts=PROMPTS, runs_dir=tmp_path, clock=clock, harness_commit=COMMIT)
    run_dir = tmp_path / RUN_ID
    assert lab.calls[-1] == "down" and (run_dir / "manifest.json").exists() and not (run_dir / "manifest.partial.json").exists()
    assert validate_run_dir(run_dir, include_score=False) == []


def test_a_stack_that_survives_teardown_is_reported(tmp_path):
    _, _, notes, *_ = make(tmp_path, [text_reply()], lab_kwargs={"left_after_down": ["containers:1"]})
    assert notes["left_after_down"] == ["containers:1"]


def test_a_failed_teardown_is_recorded_shown_and_leaves_the_runs_own_outcome_alone(tmp_path):
    # `down` raising means nothing was counted afterwards (`left_after_down` is never set), so the CLI summary
    # must say so: it used to print "validation: ok" and nothing else.
    run_dir, manifest, notes, *_ = make(tmp_path, [text_reply()], lab_kwargs={"fail_at": "down"})
    assert "down failed on purpose" in notes["down_error"] and "left_after_down" not in notes
    assert manifest["termination_reason"] == "agent_stopped"        # the model's own ending, not a harness_error
    assert "WARNING: teardown failed" in summarize(run_dir) and "down failed on purpose" in summarize(run_dir)
    assert validate_run_dir(run_dir, include_score=False) == []


def test_ctrl_c_during_teardown_still_writes_the_record_and_then_propagates(tmp_path):
    class InterruptedDown(FakeLab):
        def down(self):
            self._step("down")
            raise KeyboardInterrupt

    clock = FakeClock()
    lab = InterruptedDown(clock, run_dir=tmp_path)
    with pytest.raises(KeyboardInterrupt):
        execute_run(variant="B", condition="no_hint", lab=lab, model=FakeModel([text_reply()], clock),
                    prompts=PROMPTS, runs_dir=tmp_path, clock=clock, harness_commit=COMMIT,
                    limits=Limits(text_only_limit=1))
    run_dir = tmp_path / RUN_ID
    notes = json.loads((run_dir / "harness_notes.json").read_text(encoding="utf-8"))
    assert "KeyboardInterrupt" in notes["down_error"]
    assert (run_dir / "manifest.json").exists() and not (run_dir / "manifest.partial.json").exists()
    assert validate_run_dir(run_dir, include_score=False) == []


def test_an_interrupt_during_teardown_does_not_replace_the_one_that_ended_the_run(tmp_path):
    class InterruptedDown(FakeLab):
        def down(self):
            self._step("down")
            raise KeyboardInterrupt("second")

    clock = FakeClock()
    lab = InterruptedDown(clock, run_dir=tmp_path)
    with pytest.raises(KeyboardInterrupt) as raised:
        execute_run(variant="B", condition="no_hint", lab=lab, model=FakeModel([KeyboardInterrupt("first")], clock),
                    prompts=PROMPTS, runs_dir=tmp_path, clock=clock, harness_commit=COMMIT)
    assert raised.value.args == ("first",)               # the interrupt that ended the run is the one that propagates
    notes = json.loads((tmp_path / RUN_ID / "harness_notes.json").read_text(encoding="utf-8"))
    assert "KeyboardInterrupt: second" in notes["down_error"]     # and the second one is still on record


def test_target_down_is_recorded_with_the_final_health(tmp_path):
    health = iter([True, False, False, False])          # healthy at the start, gone after the first command
    _, manifest, *_ = make(tmp_path, [command("ls"), command("ls")], lab_kwargs={"healthy": lambda: next(health)})
    assert (manifest["termination_reason"], manifest["target_health_start"], manifest["target_health_end"]) \
        == ("target_down", "healthy", "unhealthy")


def test_development_runs_are_marked_in_the_notes(tmp_path):
    run_dir, _, notes, *_ = make(tmp_path, [text_reply()], dirty=["harness/agent.py"])
    assert notes["dirty_paths"] == ["harness/agent.py"] and "DEVELOPMENT RUN" in summarize(run_dir)


# --- scoring ------------------------------------------------------------------------------

def test_the_scorer_runs_on_the_finished_directory_and_its_verdict_is_recorded(tmp_path):
    from scorer import score_run_dir
    run_dir, _, notes, *_ = make(tmp_path, [command("ls"), submit("a guess")], score_fn=lambda d: score_run_dir(d, COMMIT))
    score = json.loads((run_dir / "score.json").read_text(encoding="utf-8"))
    assert validate_record("score", score) == [] and (score["flag_submitted"], score["pass"]) == (True, False)
    assert notes["score"]["pass"] is False
    assert validate_run_dir(run_dir) == []              # and the directory still validates WITH the score in it


def test_a_scoring_failure_is_recorded_not_raised(tmp_path):
    def broken(_dir):
        raise RuntimeError("scoring code is dirty")

    run_dir, _, notes, *_ = make(tmp_path, [text_reply()], score_fn=broken)
    assert "scoring code is dirty" in notes["score_error"] and not (run_dir / "score.json").exists()


# --- the seed, the lock, the orphans ------------------------------------------------------------

@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_a_new_seed_is_valid_and_random_for_every_variant(variant):
    first, second = new_seed(variant), new_seed(variant)
    assert first["variant_config"] == VARIANTS[variant]["variant_config"]
    assert ("shortcut_path" in first["variant_config"]) == (variant == "D")
    assert first["flag"].startswith("FLAG-") and len(first["secret_key"]) >= 43
    assert first["flag"] != second["flag"] and first["admin_password"] != second["admin_password"]


def test_the_lock_admits_one_harness_at_a_time_and_is_released(tmp_path):
    with run_lock(tmp_path):
        with pytest.raises(HarnessError, match="another harness"):
            with run_lock(tmp_path):
                pass
    with run_lock(tmp_path):      # released after the first one ended
        pass


def test_the_lock_is_released_when_the_run_raises(tmp_path):
    with pytest.raises(RuntimeError):
        with run_lock(tmp_path):
            raise RuntimeError("boom")
    with run_lock(tmp_path):
        pass


def test_orphans_are_runs_with_a_partial_manifest_and_no_manifest(tmp_path):
    (tmp_path / "aaa").mkdir()
    (tmp_path / "aaa" / "manifest.partial.json").write_text("{}")
    (tmp_path / "bbb").mkdir()
    (tmp_path / "bbb" / "manifest.partial.json").write_text("{}")
    (tmp_path / "bbb" / "manifest.json").write_text("{}")
    (tmp_path / "hand").mkdir()
    assert find_orphans(tmp_path) == ["aaa"] and find_orphans(tmp_path / "missing") == []


# --- provenance ------------------------------------------------------------------------------

@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_git_provenance_names_the_dirty_code_paths_exactly(tmp_path):
    # A real run printed "ocker-compose.yml": the first porcelain line starts with a space (" M path"), and
    # stripping the whole output ate it. The first path must come back whole.
    def git(*args):
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "test")
    for name in ("harness/agent.py", "prompts/system.md", "docker-compose.yml"):
        (tmp_path / name).parent.mkdir(exist_ok=True)
        (tmp_path / name).write_text("original")
    git("add", ".")
    git("commit", "-q", "-m", "initial")
    commit, dirty = git_provenance(tmp_path)
    assert re.fullmatch(r"[0-9a-f]{40}", commit) and dirty == []

    (tmp_path / "docker-compose.yml").write_text("changed")        # the tracked file whose status line starts with a space
    (tmp_path / "prompts" / "new.txt").write_text("untracked")
    (tmp_path / "notes.txt").write_text("not harness code")        # outside the code paths: never counted
    _, dirty = git_provenance(tmp_path)
    assert sorted(dirty) == ["docker-compose.yml", "prompts/new.txt"]


# --- the reviews' findings (D-065) ------------------------------------------------------------

def test_a_target_the_agent_crashed_stays_target_down_even_though_the_end_clock_cannot_be_read(tmp_path):
    # The methodology review's finding: measuring the clock of a dead target fails, and that used to
    # override target_down with harness_error, turning a legitimate agent-caused outcome into a harness bug
    # that is investigated and never counted. The end measurement is simply null then.
    health = iter([True, False, False, False])
    clock = FakeClock()
    lab = FakeLab(clock, run_dir=tmp_path, healthy=lambda: next(health))
    lab.fail_clock_after_first = True
    run_dir = execute_run(variant="B", condition="no_hint", lab=lab, model=FakeModel([command("ls")] * 3, clock),
                          prompts=PROMPTS, runs_dir=tmp_path, clock=clock, harness_commit=COMMIT,
                          executor_factory=lambda _l: FakeExecutor(clock))
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert (manifest["termination_reason"], manifest["harness_error"]) == ("target_down", None)
    assert manifest["clock_offset_end_ms"] is None and manifest["target_health_end"] == "unhealthy"
    assert validate_run_dir(run_dir, include_score=False) == []


def test_an_exception_in_the_middle_of_the_loop_still_leaves_a_valid_run_with_its_log(tmp_path):
    # The second command raises. The first step is already on disk, so the record needs the loop's true
    # start (not the moment of the failure), and the target's log must still be collected.
    class FailsOnSecond:
        def __init__(self, clock):
            self.clock, self.count = clock, 0

        def run(self, text):
            self.count += 1
            if self.count == 2:
                raise RuntimeError("docker exec could not start")
            self.clock.advance(1)
            return outcome("ok\n")

    clock = FakeClock()
    lab = FakeLab(clock, run_dir=tmp_path)
    run_dir = execute_run(variant="B", condition="no_hint", lab=lab, model=FakeModel([command("a"), command("b")], clock, 2),
                          prompts=PROMPTS, runs_dir=tmp_path, clock=clock, harness_commit=COMMIT,
                          executor_factory=lambda _l: FailsOnSecond(clock))
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    steps = [json.loads(line) for line in (run_dir / "steps.jsonl").read_text(encoding="utf-8").splitlines()]
    assert manifest["termination_reason"] == "harness_error" and "docker exec could not start" in manifest["harness_error"]
    assert len(steps) == 1 and "collect_events" in lab.calls
    assert manifest["started_at"] == "2026-11-12T10:00:00+00:00"       # before the first model call, not when it failed
    assert validate_run_dir(run_dir, include_score=False) == []


def test_a_dead_attacker_ends_the_run_as_a_harness_error_before_the_model_sees_docker_text(tmp_path):
    clock = FakeClock()
    lab = FakeLab(clock, run_dir=tmp_path)
    lab.attacker_alive = False
    model = FakeModel([command("ls"), command("ls")], clock)
    run_dir = execute_run(variant="B", condition="no_hint", lab=lab, model=model, prompts=PROMPTS, runs_dir=tmp_path,
                          clock=clock, harness_commit=COMMIT,
                          executor_factory=lambda _l: FakeExecutor(clock, [outcome("Error response from daemon: container lab-x is not running\n", 1)]))
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["termination_reason"] == "harness_error" and "attacker container is not running" in manifest["harness_error"]
    assert len(model.requests) == 1          # the daemon's text was recorded in the step, never sent to the model
    assert validate_run_dir(run_dir, include_score=False) == []


def _dead_attacker_run(tmp_path, facts):
    clock = FakeClock()
    lab = FakeLab(clock, run_dir=tmp_path)
    lab.attacker_alive, lab.attacker_facts = False, facts
    run_dir = execute_run(variant="B", condition="no_hint", lab=lab, model=FakeModel([command("ls")], clock), prompts=PROMPTS,
                          runs_dir=tmp_path, clock=clock, harness_commit=COMMIT,
                          executor_factory=lambda _l: FakeExecutor(clock), score_fn=default_score_stub)
    return run_dir, json.loads((run_dir / "harness_notes.json").read_text(encoding="utf-8"))


def default_score_stub(run_dir):
    """Like the real scorer, leaves a score.json behind: outcome() reads that file."""
    score = {"pass": False, "milestones": []}
    (run_dir / "score.json").write_text(json.dumps(score), encoding="utf-8")
    return score, []


def test_a_dead_attacker_records_what_docker_says_and_the_outcome_follows_oom_killed(tmp_path):
    # D-074 to-build item 2: the facts are recorded as facts. The outcome is decided from them, not from the message.
    oom = {"running": False, "oom_killed": True, "exit_code": 137, "finished_at": "2026-11-12T10:00:00Z"}
    run_dir, notes = _dead_attacker_run(tmp_path / "oom", oom)
    assert notes["attacker_stopped"] == oom
    assert (load_outcome(run_dir).kind, load_outcome(run_dir).passed) == ("fail", False)
    plain = {"running": False, "oom_killed": False, "exit_code": 137, "finished_at": "2026-11-12T10:00:00Z"}
    run_dir, notes = _dead_attacker_run(tmp_path / "plain", plain)
    assert notes["attacker_stopped"] == plain and load_outcome(run_dir).kind == "replaced"


def test_an_unreadable_attacker_state_is_never_taken_for_an_oom_kill(tmp_path):
    unreadable = {"running": None, "oom_killed": None, "exit_code": None, "finished_at": None}
    run_dir, notes = _dead_attacker_run(tmp_path, unreadable)
    assert notes["attacker_stopped"]["oom_killed"] is None and load_outcome(run_dir).kind == "replaced"


def test_a_flooded_log_is_recorded_as_a_structured_note_and_is_a_fail(tmp_path):
    from lab import LogFloodError

    class Flooding(FakeLab):
        def collect_events(self):
            self._step("collect_events")
            raise LogFloodError("the target's log is 60 MiB: the agent flooded it", 60 * 2 ** 20)

    clock = FakeClock()
    lab = Flooding(clock, run_dir=tmp_path)
    run_dir = execute_run(variant="B", condition="no_hint", lab=lab, model=FakeModel([submit("x")], clock), prompts=PROMPTS,
                          runs_dir=tmp_path, clock=clock, harness_commit=COMMIT,
                          executor_factory=lambda _l: FakeExecutor(clock), score_fn=default_score_stub)
    notes = json.loads((run_dir / "harness_notes.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert notes["log_flood"] == {"log_bytes": 60 * 2 ** 20} and manifest["termination_reason"] == "harness_error"
    assert (load_outcome(run_dir).kind, load_outcome(run_dir).passed) == ("fail", False)   # an agent cause beats the correct submit


def test_the_summary_shows_the_outcome(tmp_path):
    run_dir, *_ = make(tmp_path, [submit("a guess")], score_fn=default_score_stub)
    assert "outcome: scored (pass=False) - submitted" in summarize(run_dir)
    run_dir, *_ = make(tmp_path / "b", [command("ls"), ModelError("slow", retries=4, kind="model_error")], score_fn=default_score_stub)
    assert "outcome: replaced - api_error (model_error)" in summarize(run_dir)


def test_the_target_is_probed_with_retries_during_the_run(tmp_path):
    class Recording(FakeLab):
        def health(self, attempts=1):
            self.calls.append(f"health:{attempts}")
            return True

    clock = FakeClock()
    lab = Recording(clock, run_dir=tmp_path)
    execute_run(variant="B", condition="no_hint", lab=lab, model=FakeModel([command("ls"), text_reply()], clock), prompts=PROMPTS,
                runs_dir=tmp_path, clock=clock, harness_commit=COMMIT, executor_factory=lambda _l: FakeExecutor(clock),
                limits=Limits(text_only_limit=1))
    assert "health:4" in lab.calls            # after the command; the start and final probes are single


def test_the_api_error_kind_and_the_loops_own_ending_are_structured_in_the_notes(tmp_path):
    _, manifest, notes, *_ = make(tmp_path, [command("ls"), ModelError("slow down", retries=4, kind="model_error")])
    assert (manifest["termination_reason"], notes["api_error_kind"]) == ("api_error", "model_error")
    _, manifest, notes, *_ = make(tmp_path / "b", [submit("x")], lab_kwargs={"fail_at": "collect_events"})
    assert (manifest["termination_reason"], notes["loop_ended_as"]) == ("harness_error", "submitted")


def test_output_the_model_is_sent_is_the_shortened_text_not_the_stored_one(tmp_path):
    # The methodology review's finding: with output_full equal to output_sent in every fake, sending the
    # wrong one to the model passed every test. Here they differ, and each is recorded where it belongs.
    long = outcome("short view\n", full="THE WHOLE STORED OUTPUT, much longer\n")
    _, _, _, steps, _, model = make(tmp_path, [command("cat big"), text_reply()], results=[long])
    assert steps[0]["output_full"] == "THE WHOLE STORED OUTPUT, much longer\n" and steps[0]["output_sent_to_model"] == "short view\n"
    shown = model.requests[1]["messages"][-1]["content"][0]["toolResult"]["content"][0]["text"]
    assert shown == "short view\n" and "WHOLE" not in json.dumps(model.requests[1]["messages"])


# --- the local backend (D-067) ---------------------------------------------------------------

LOCAL_RUNTIME = {
    "runtime": "llama.cpp llama-server", "runtime_version": "b12478-8d1599fca", "weights_sha256": "sha256:" + "d" * 64,
    "quantization": "Q4_K_M", "context_length": 16384, "seed": 7, "chat_template_sha256": "sha256:" + "c" * 64,
    "rendered_prefix_sha256": "sha256:" + "e" * 64, "refusal_modified": False,
}


class FakeLocalModel(FakeModel):
    """A local model: no Bedrock request id, a prepare() the run must call first, a local_runtime block."""

    backend = "local"
    model_id = "Qwen/Qwen3-8B"
    local_runtime = LOCAL_RUNTIME

    def __init__(self, script, clock, lab=None, prefix="RENDERED PREFIX", error=None):
        super().__init__([dataclasses.replace(r, request_id=None) if hasattr(r, "request_id") else r for r in script], clock)
        self.lab, self.prefix, self.error, self.docker_calls_before_prepare = lab, prefix, error, None

    pin = type("Pin", (), {"weights_sha256": "sha256:" + "d" * 64})()
    weights_path = None

    def prepare(self, system, tool_config, opening):
        from local_model import ServerCheckError
        self.docker_calls_before_prepare = list(self.lab.calls) if self.lab else None
        if self.error:
            raise ServerCheckError(self.error)
        return {"rendered_prefix": self.prefix, "build_info": "b12478-8d1599fca", "chat_template_sha256": "sha256:" + "c" * 64,
                "rendered_prefix_sha256": "sha256:" + "e" * 64, "weights_path": self.weights_path}


def run_local(tmp_path, script, *, seed=None, limits=None, **model_kwargs):
    clock = FakeClock()
    lab = FakeLab(clock, run_dir=tmp_path)
    model = FakeLocalModel(script, clock, lab=lab, **model_kwargs)
    run_dir = execute_run(variant="B", condition="no_hint", lab=lab, model=model, prompts=PROMPTS, runs_dir=tmp_path, clock=clock,
                          harness_commit=COMMIT, seed=seed or new_seed("B"), executor_factory=lambda _l: FakeExecutor(clock),
                          limits=limits if limits is not None else Limits(text_only_limit=1),
                          inference=INFERENCE_CONFIG)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    notes = json.loads((run_dir / "harness_notes.json").read_text(encoding="utf-8"))
    return run_dir, manifest, notes, lab, model


def test_a_local_run_has_a_local_runtime_and_no_region_and_validates(tmp_path):
    run_dir, manifest, notes, lab, model = run_local(tmp_path, [command("ls"), text_reply("done")])
    assert (manifest["backend"], manifest["model_id"], manifest["local_runtime"]) == ("local", "Qwen/Qwen3-8B", LOCAL_RUNTIME)
    assert "region" not in manifest
    steps = [json.loads(line) for line in (run_dir / "steps.jsonl").read_text(encoding="utf-8").splitlines()]
    assert all("bedrock_request_id" not in s for s in steps)
    assert validate_run_dir(run_dir, include_score=False) == []
    assert "rendered_prefix" not in notes["local_server"] and notes["local_server"]["build_info"] == "b12478-8d1599fca"


def test_the_server_is_checked_before_any_docker_work(tmp_path):
    *_, lab, model = run_local(tmp_path, [text_reply()])
    assert model.docker_calls_before_prepare == []          # nothing had touched Docker when the check ran


def test_a_server_that_is_not_the_pinned_one_ends_the_run_before_anything_starts(tmp_path):
    run_dir, manifest, _, lab, model = run_local(tmp_path, [text_reply()], error="the model server does not match the pin: build 'b1'")
    assert manifest["termination_reason"] == "harness_error" and "does not match the pin" in manifest["harness_error"]
    assert lab.calls == ["down"] and model.requests == []     # no sweep, no up, no model call: only the final teardown
    assert validate_run_dir(run_dir, include_score=False) == []


@pytest.mark.parametrize("which,name", [("flag", "flag"), ("admin_password", "admin_password"), ("secret_key", "secret_key")])
def test_a_secret_in_the_rendered_local_request_ends_the_run_naming_it_but_not_its_value(tmp_path, which, name):
    seed = new_seed("B")
    run_dir, manifest, *_ , model = run_local(tmp_path, [text_reply()], seed=seed, prefix=f"system ... {seed[which]} ...")
    assert manifest["termination_reason"] == "harness_error" and f"contains {name}" in manifest["harness_error"]
    assert seed[which] not in manifest["harness_error"] and model.requests == []


def test_the_run_id_in_the_rendered_request_is_caught_too(tmp_path):
    _, manifest, _, _, model = run_local(tmp_path, [text_reply()], prefix=f"id {RUN_ID}")
    assert manifest["termination_reason"] == "harness_error" and "run_id" in manifest["harness_error"]
    assert model.requests == []



def test_the_weights_file_the_server_loaded_is_hashed_against_the_pin(tmp_path, monkeypatch):
    import run as run_module
    seen = []
    monkeypatch.setattr(run_module, "verify_weights", lambda path, expected: seen.append((str(path), expected)))
    FakeLocalModel.weights_path = "C:\\models\\Qwen3-8B-Q4_K_M.gguf"
    try:
        _, manifest, notes, lab, _ = run_local(tmp_path, [text_reply()])
    finally:
        FakeLocalModel.weights_path = None
    assert seen == [("C:\\models\\Qwen3-8B-Q4_K_M.gguf", "sha256:" + "d" * 64)]
    assert manifest["termination_reason"] == "agent_stopped" and "weights_path" not in notes["local_server"]


def test_weights_that_do_not_match_the_pin_end_the_run_before_any_docker_work(tmp_path, monkeypatch):
    import run as run_module
    from local_model import ServerCheckError

    def refuse(path, expected):
        raise ServerCheckError("Qwen3-8B-Q4_K_M.gguf does not match the pinned SHA-256")

    monkeypatch.setattr(run_module, "verify_weights", refuse)
    FakeLocalModel.weights_path = "C:\\models\\Qwen3-8B-Q4_K_M.gguf"
    try:
        _, manifest, _, lab, model = run_local(tmp_path, [text_reply()])
    finally:
        FakeLocalModel.weights_path = None
    assert manifest["termination_reason"] == "harness_error" and "pinned SHA-256" in manifest["harness_error"]
    assert lab.calls == ["down"] and model.requests == []


# --- scoring a development run over uncommitted scoring code (D-086) -----------------------------

def test_default_score_refuses_uncommitted_scoring_code_unless_the_run_allows_dirty(tmp_path, monkeypatch):
    import scorer

    calls = []
    monkeypatch.setattr(scorer, "scorer_provenance", lambda: ("d" * 40, ["scoring/scorer.py"]))
    monkeypatch.setattr(scorer, "resolve_scorer_commit",
                        lambda: (_ for _ in ()).throw(scorer.CommitError("scoring code has uncommitted changes")))
    monkeypatch.setattr(scorer, "score_run_dir", lambda run_dir, commit, **kw: calls.append((commit, kw)) or ({}, []))
    with pytest.raises(scorer.CommitError):
        default_score(tmp_path)                                      # strict by default
    assert calls == []
    default_score(tmp_path, allow_dirty=True)
    assert calls == [("d" * 40, {"scorer_dirty_paths": ["scoring/scorer.py"]})]


def test_the_summary_reads_the_development_marker_from_score_json_never_from_the_notes(tmp_path):
    # score.json is the only authority (D-086). The notes hold a run-time snapshot with no marker, so a rescore,
    # which rewrites score.json and not the notes, can never leave the summary saying the old thing.
    def score_fn(run_dir):
        (run_dir / "score.json").write_text(json.dumps({"scorer_dirty_paths": ["scoring/scorer.py"]}), encoding="utf-8")
        return {"pass": False, "milestones": []}, []

    run_dir, _, notes, *_ = make(tmp_path, [text_reply()], score_fn=score_fn)
    assert "scorer_dirty_paths" not in notes["score"]
    assert "DEVELOPMENT SCORE" in summarize(run_dir) and "scoring/scorer.py" in summarize(run_dir)
    (run_dir / "score.json").write_text(json.dumps({"pass": False}), encoding="utf-8")     # a clean rescore
    assert "DEVELOPMENT SCORE" not in summarize(run_dir)


def test_an_unreadable_score_json_never_breaks_the_summary(tmp_path):
    run_dir, *_ = make(tmp_path, [text_reply()], score_fn=lambda _d: ({"pass": False, "milestones": []}, []))
    (run_dir / "score.json").write_text("{not json", encoding="utf-8")
    assert "DEVELOPMENT SCORE" not in summarize(run_dir)


# --- the study-data guard (D-086) ----------------------------------------------------------------

def test_study_validation_rejects_a_development_score_and_a_clean_rescore_clears_it(tmp_path):
    import scorer

    run_dir, *_ = make(tmp_path, [text_reply()])
    scorer.score_run_dir(run_dir, "d" * 40, scorer_dirty_paths=["scoring/scorer.py"])
    assert validate_run_dir(run_dir) == []                              # a valid record, as every development score is
    problems = validate_run_dir(run_dir, study=True)
    assert len(problems) == 1 and "development score" in problems[0] and "scoring/scorer.py" in problems[0]
    scorer.score_run_dir(run_dir, "d" * 40)                             # replaced by an ordinary score
    assert validate_run_dir(run_dir, study=True) == []


def test_study_validation_rejects_a_run_made_with_uncommitted_code_even_when_its_score_is_clean(tmp_path):
    import scorer

    run_dir, *_ = make(tmp_path, [text_reply()], dirty=("harness/agent.py",))
    scorer.score_run_dir(run_dir, "d" * 40)
    assert validate_run_dir(run_dir) == []
    problems = validate_run_dir(run_dir, study=True)
    assert len(problems) == 1 and "development run" in problems[0] and "harness/agent.py" in problems[0]


def test_study_validation_of_an_ordinary_run_is_empty_and_an_unreadable_notes_file_is_not_trusted(tmp_path):
    run_dir, *_ = make(tmp_path, [text_reply()])
    assert validate_run_dir(run_dir, study=True) == []
    (run_dir / "harness_notes.json").write_text("{not json", encoding="utf-8")
    assert any("harness_notes.json" in problem for problem in validate_run_dir(run_dir, study=True))
