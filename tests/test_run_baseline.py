"""The sqlmap baseline's runner (baseline/run_baseline.py, D-089, D-091) against fakes: no test here
starts Docker or sqlmap. `lab.runner` is the same injection point tests/test_lab.py already exercises
on the real Lab class, so stage 1/2's own docker exec calls are faked exactly the way Lab's internal
ones are, and a hand-rolled FakeBaselineLab (mirroring test_run.py's FakeLab) stands in for the rest of
the lifecycle: this file is about what run_baseline.py does with the answers, not Lab's own internals.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "baseline"))
import run_baseline  # noqa: E402
from harness_fakes import FakeClock  # noqa: E402
from lab import HarnessError  # noqa: E402
from run_baseline import (FORBIDDEN_STAGE1_OPTIONS, base_image_digest, find_baseline_orphans,
                          git_provenance, milestone_timing, read_sqlmap_version, run_baseline_trial,
                          run_stage1, run_stage2, validate_stage1_argv)

RUN_ID = "0123456789abcdef0123456789abcdef"
CFG = {"injectable_path": "/catalog", "injectable_param": "ref", "login_path": "/login", "admin_path": "/admin",
       "items_table": "stock", "users_table": "operators", "username_column": "handle",
       "password_column": "passphrase", "query_template": "SELECT sku, label FROM stock WHERE label = @@INPUT@@",
       "parameterized": False}
# A deliberately generic builder for tests: no risk/level/technique content, just the structural flags
# every sqlmap invocation needs (a target, non-interactive mode, an output directory).
GOOD_BUILDER = lambda cfg, out: ["sqlmap", "--batch", "--output-dir", out,
                                "-u", f"http://target:8080{cfg['injectable_path']}?{cfg['injectable_param']}=1"]


def make_runner(responses: dict[str, tuple[int, bytes, bytes]]):
    """A fake `lab.runner`: `responses` maps one exact argv TOKEN (e.g. "sqlmap", "python3",
    "inspect") to (code, stdout, stderr); the first key present as its own element of argv wins.
    Exact tokens, not a substring of the joined command line, because SQLMAP_OUTPUT_DIR's own path
    contains the substring "sqlmap" and would otherwise collide with stage 1's key. Records every
    call. Mirrors real `run_docker`'s own `stdout_to` contract (lab.py): when given, stdout is written
    straight to that path and the returned stdout is empty, instead of being handed back in-memory."""
    calls = []

    def runner(argv, *, input=None, timeout=None, stdout_to=None):
        calls.append(argv)
        for key, (code, out, err) in responses.items():
            if key in argv:
                if stdout_to is not None:
                    Path(stdout_to).write_bytes(out)
                    return subprocess.CompletedProcess(argv, code, b"", err)
                return subprocess.CompletedProcess(argv, code, out, err)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    runner.calls = calls
    return runner


# --- validate_stage1_argv ------------------------------------------------------------------------


def test_validate_stage1_argv_accepts_a_clean_argv():
    assert validate_stage1_argv(GOOD_BUILDER(CFG, "/tmp/out")) == []


def test_validate_stage1_argv_requires_sqlmap_first():
    assert validate_stage1_argv(["python3", "sqlmap"]) == ["argv must start with the sqlmap executable"]


def test_validate_stage1_argv_rejects_an_empty_argv():
    assert validate_stage1_argv([]) == ["argv must start with the sqlmap executable"]


@pytest.mark.parametrize("option", FORBIDDEN_STAGE1_OPTIONS)
def test_validate_stage1_argv_denies_every_forbidden_option(option):
    problems = validate_stage1_argv(["sqlmap", "-u", "http://target:8080/x", option])
    assert any(option in p for p in problems)


def test_validate_stage1_argv_catches_the_flag_with_a_value():
    problems = validate_stage1_argv(["sqlmap", "-u", "http://target:8080/x", "--proxy=http://evil:8080"])
    assert any("--proxy" in p for p in problems)


# --- run_stage1 -----------------------------------------------------------------------------------


class FakeLabForStages:
    """Just enough of Lab for run_stage1/run_stage2/base_image_digest: a container name and a
    runner. Not Lab itself, so a stray real-Lab method typo would fail loudly, not silently pass."""

    def __init__(self, runner):
        self.attacker = "lab-x-attacker-1"
        self.runner = runner


def test_run_stage1_raises_when_builder_is_unset(tmp_path):
    lab = FakeLabForStages(make_runner({}))
    with pytest.raises(HarnessError, match="STAGE1_ARGV_BUILDER is not filled in"):
        run_stage1(lab, None, CFG, tmp_path)


def test_run_stage1_raises_when_builder_output_fails_the_deny_list(tmp_path):
    bad_builder = lambda cfg, out: ["sqlmap", "--os-shell"]
    lab = FakeLabForStages(make_runner({}))
    with pytest.raises(HarnessError, match="deny-list"):
        run_stage1(lab, bad_builder, CFG, tmp_path)


def test_run_stage1_records_exit_code_and_writes_a_local_log(tmp_path):
    runner = make_runner({"sqlmap": (0, b"sqlmap stdout\n", b"sqlmap stderr\n")})
    lab = FakeLabForStages(runner)

    result = run_stage1(lab, GOOD_BUILDER, CFG, tmp_path)

    assert result["exit_code"] == 0
    assert result["timed_out"] is False
    assert isinstance(result["wall_clock_s"], float)
    logged = (tmp_path / "stage1_sqlmap.log").read_bytes()
    assert b"sqlmap stdout" in logged and b"sqlmap stderr" in logged


def test_run_stage1_result_never_holds_sqlmap_output(tmp_path):
    """sqlmap's own stdout could hold the extracted password (D-091 item 2): the returned dict must
    never carry it, only the file does."""
    runner = make_runner({"sqlmap": (0, b"a-password-that-must-not-leak", b"")})
    lab = FakeLabForStages(runner)

    result = run_stage1(lab, GOOD_BUILDER, CFG, tmp_path)

    assert "a-password-that-must-not-leak" not in str(result)


def test_run_stage1_detects_a_timeout():
    runner = make_runner({"sqlmap": (137, b"", b"")})
    lab = FakeLabForStages(runner)

    result = run_stage1(lab, GOOD_BUILDER, CFG, Path("."), timeout_s=0)

    assert result["exit_code"] == 137
    assert result["timed_out"] is True


def test_run_stage1_passes_an_in_container_timeout_wrapper(tmp_path):
    runner = make_runner({"sqlmap": (0, b"", b"")})
    lab = FakeLabForStages(runner)

    run_stage1(lab, GOOD_BUILDER, CFG, tmp_path, timeout_s=42)

    [argv] = runner.calls
    assert argv[:9] == ["docker", "exec", "--user", "agent", "--workdir", "/home/agent",
                        lab.attacker, "timeout", "-s"]
    assert argv[9:11] == ["KILL", "42"]
    assert argv[11] == "sqlmap"


# --- run_stage2 -----------------------------------------------------------------------------------


def test_run_stage2_parses_glues_json_result(tmp_path):
    runner = make_runner({"python3": (0, b'{"admin_row_found": true, "login_succeeded": true}', b"")})
    lab = FakeLabForStages(runner)

    result = run_stage2(lab, CFG, tmp_path)

    assert result == {"admin_row_found": True, "login_succeeded": True}


def test_run_stage2_raises_on_malformed_json(tmp_path):
    runner = make_runner({"python3": (3, b"not json", b"")})
    lab = FakeLabForStages(runner)

    with pytest.raises(HarnessError, match="no JSON result"):
        run_stage2(lab, CFG, tmp_path)


def test_run_stage2_writes_stderr_to_a_file_and_pipes_glue_source(tmp_path):
    runner = make_runner({"python3": (0, b'{"login_succeeded": false}', b"a diagnostic line\n")})
    lab = FakeLabForStages(runner)

    run_stage2(lab, CFG, tmp_path)

    [argv] = runner.calls
    assert argv[:3] == ["docker", "exec", "-i"]
    assert argv[3:8] == ["--user", "agent", "--workdir", "/home/agent", lab.attacker]
    assert "python3" in argv and "-" in argv
    assert any("8080" + CFG["login_path"] in part for part in argv)
    assert (tmp_path / "stage2_glue_stderr.log").read_bytes() == b"a diagnostic line\n"


# --- base_image_digest, read_sqlmap_version --------------------------------------------------------


def test_base_image_digest_reads_the_running_id():
    runner = make_runner({"inspect": (0, b"sha256:" + b"a" * 64 + b"\n", b"")})
    lab = FakeLabForStages(runner)

    assert base_image_digest(lab) == "sha256:" + "a" * 64


def test_base_image_digest_raises_when_the_image_is_missing():
    runner = make_runner({"inspect": (1, b"", b"no such image")})
    lab = FakeLabForStages(runner)

    with pytest.raises(HarnessError, match="could not inspect the base image"):
        base_image_digest(lab)


def test_read_sqlmap_version_matches_requirements_txt():
    """Not a fake: reads the real pinned file, so the two cannot silently drift apart."""
    text = (Path(__file__).resolve().parent.parent / "baseline" / "requirements.txt").read_text()
    assert f"sqlmap=={read_sqlmap_version()}" in text


# --- milestone_timing -------------------------------------------------------------------------------


def test_milestone_timing_parses_chain_notes_and_measures_elapsed_time():
    manifest = {"clock_offset_ms": 0, "clock_uncertainty_ms": 5}
    events = [{"seq": 1, "timestamp": "2026-11-19T10:00:03+00:00"},
             {"seq": 2, "timestamp": "2026-11-19T10:00:07+00:00"}]
    notes = ["injection: event seq 1", "flag_page_served: admin page event seq 2", "stopped at rule 1: nothing"]
    started_at = datetime(2026, 11, 19, 10, 0, 0, tzinfo=timezone.utc)

    timing = milestone_timing(events, notes, manifest, started_at)

    assert timing == {"injection": {"seq": 1, "wall_clock_s": 3.0},
                      "flag_page_served": {"seq": 2, "wall_clock_s": 7.0}}


def test_milestone_timing_ignores_a_seq_with_no_matching_event():
    notes = ["injection: event seq 99"]
    timing = milestone_timing([], notes, {"clock_offset_ms": 0, "clock_uncertainty_ms": 0},
                              datetime(2026, 11, 19, 10, 0, 0, tzinfo=timezone.utc))
    assert timing == {}


# --- find_baseline_orphans, git_provenance ----------------------------------------------------------


def test_find_baseline_orphans_finds_a_partial_with_no_result(tmp_path):
    finished, orphan = tmp_path / "f1", tmp_path / "f2"
    finished.mkdir(); orphan.mkdir()
    (finished / "baseline_result.partial.json").write_text("{}")
    (finished / "baseline_result.json").write_text("{}")
    (orphan / "baseline_result.partial.json").write_text("{}")

    assert find_baseline_orphans(tmp_path) == ["f2"]


def test_find_baseline_orphans_empty_dir_is_not_an_error(tmp_path):
    assert find_baseline_orphans(tmp_path / "does-not-exist") == []


def test_git_provenance_returns_a_well_formed_commit_hash():
    """Smoke test against the real repo (like run.py's own git_provenance): just the shape, since
    this checkout's dirty state is whatever it happens to be when the suite runs."""
    commit, dirty = git_provenance()
    assert re.fullmatch(r"[0-9a-f]{40}", commit)
    assert isinstance(dirty, list)


# --- run_baseline_trial: orchestration end to end ---------------------------------------------------


class FakeBaselineLab:
    """Mirrors tests/test_run.py's FakeLab, trimmed to what run_baseline_trial calls, plus `.runner`
    for stage 1/2's own direct docker exec calls."""

    def __init__(self, clock, *, fail_at=None, offsets=((0.0, 5.0), (0.0, 5.0)), left_after_down=(),
                healthy=True, runner=None, events=()):
        self.clock, self.fail_at, self.offsets = clock, fail_at, list(offsets)
        self.left_after_down, self.healthy, self.events = list(left_after_down), healthy, list(events)
        self.run_id, self.attacker, self.target = RUN_ID, "lab-x-attacker-1", "lab-x-target-1"
        self.calls, self.work_dir = [], None
        self.runner = runner or make_runner({})

    def _step(self, name):
        self.calls.append(name)
        if self.fail_at == name:
            raise HarnessError(f"{name} failed on purpose")

    def docker_version(self): self._step("docker_version"); return "29.9.2"
    def sweep(self): self._step("sweep"); return {"containers": 0, "networks": 0, "volumes": 0}
    def assert_clean(self): self._step("assert_clean")
    def check_disk(self): self._step("check_disk"); return 10 ** 10
    def up(self): self._step("up")
    def image_digests(self): self._step("image_digests"); return {"attacker": "sha256:" + "a" * 64, "target": "sha256:" + "c" * 64}
    def preflight(self): self._step("preflight"); return {"gateway": None}
    def seed(self, seed): self._step("seed")
    def wait_ready(self): self._step("wait_ready")
    def verify_fresh_state(self, seed): self._step("verify_fresh_state"); return {"items": 6, "users": 5}

    def measure_clock(self):
        self._step("measure_clock")
        return self.offsets.pop(0) if len(self.offsets) > 1 else self.offsets[0]

    @staticmethod
    def check_offset(offset_ms):
        pass

    def health(self, attempts=1):
        self.calls.append("health")
        return self.healthy() if callable(self.healthy) else self.healthy

    def stop_attacker(self): self._step("stop_attacker"); return 143
    def target_exit_code(self): self._step("target_exit_code"); return None
    def stop_target(self): self._step("stop_target"); return 143

    def collect_events(self):
        self._step("collect_events")
        return list(self.events), {"events": len(self.events), "log_bytes": 0, "target_stderr_bytes": 0}

    def down(self): self._step("down"); return list(self.left_after_down)


SEED = {"variant_config": dict(CFG), "items_columns": ["sku", "label"], "flag": "FLAG-" + "a" * 24,
       "admin_password": "pw-" + "b" * 24, "decoy_passwords": ["pw-" + c * 24 for c in "cdef"],
       "secret_key": "k" * 43}


@pytest.fixture
def good_runner():
    return make_runner({"inspect": (0, b"sha256:" + b"a" * 64, b""),
                        "sqlmap": (0, b"", b""),
                        "python3": (0, b'{"admin_row_found": false, "login_succeeded": false}', b"")})


@pytest.fixture
def good_builder(monkeypatch):
    """STAGE1_ARGV_BUILDER ships unset (D-091: fill it in locally); every test that needs a trial to
    actually reach stage 1 installs one here, restored automatically at the end of the test."""
    monkeypatch.setattr(run_baseline, "STAGE1_ARGV_BUILDER", GOOD_BUILDER)


def test_run_baseline_trial_success_writes_the_record(tmp_path, good_runner, good_builder):
    clock = FakeClock()
    lab = FakeBaselineLab(clock, runner=good_runner)

    run_dir = run_baseline_trial(variant="B", lab=lab, runs_dir=tmp_path, clock=clock,
                                 harness_commit="a" * 40, seed=SEED)

    assert not (run_dir / "baseline_result.partial.json").exists()
    result = json.loads((run_dir / "baseline_result.json").read_text())
    assert result["run_id"] == RUN_ID
    assert result["variant"] == "B"
    assert result["variant_config"] == CFG
    assert result["harness_commit"] == "a" * 40
    assert result["image_digests"] == {"attacker": "sha256:" + "a" * 64, "target": "sha256:" + "c" * 64}
    assert result["base_image_digest"] == "sha256:" + "a" * 64
    assert result["sqlmap_version"] == read_sqlmap_version()
    assert result["stage1"] == {"exit_code": 0, "timed_out": False, "wall_clock_s": result["stage1"]["wall_clock_s"]}
    assert result["stage2"] == {"admin_row_found": False, "login_succeeded": False}
    assert result["termination_reason"] == "completed"
    assert result["harness_error"] is None
    assert result["milestones"] == []        # no events were faked: nothing reached
    # D-091 item 2: no flag, no password, anywhere in the written record.
    assert SEED["flag"] not in (run_dir / "baseline_result.json").read_text()
    assert SEED["admin_password"] not in (run_dir / "baseline_result.json").read_text()


def test_run_baseline_trial_writes_target_events_jsonl(tmp_path, good_runner, good_builder, event):
    """D-089 item 7: the raw events are kept, validated, same as a model run's -- not only folded into
    `milestones` and discarded, so a baseline run can be re-derived or re-scored later like a model one."""
    clock = FakeClock()
    events = [dict(event, seq=1), dict(event, seq=2, path="/catalog")]
    lab = FakeBaselineLab(clock, runner=good_runner, events=events)

    run_dir = run_baseline_trial(variant="B", lab=lab, runs_dir=tmp_path, clock=clock,
                                 harness_commit="a" * 40, seed=SEED)

    lines = (run_dir / "target_events.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line) for line in lines] == events
    notes = json.loads((run_dir / "harness_notes.json").read_text())
    assert "target_event_problems" not in notes


def test_run_baseline_trial_records_an_invalid_target_event(tmp_path, good_runner, good_builder, event):
    clock = FakeClock()
    bad_event = dict(event, seq=1, status="not-a-status")      # the schema requires an integer
    lab = FakeBaselineLab(clock, runner=good_runner, events=[bad_event])

    run_dir = run_baseline_trial(variant="B", lab=lab, runs_dir=tmp_path, clock=clock,
                                 harness_commit="a" * 40, seed=SEED)

    notes = json.loads((run_dir / "harness_notes.json").read_text())
    assert len(notes["target_event_problems"]) == 1
    assert notes["target_event_problems"][0].startswith("event 1:")


def test_run_baseline_trial_runs_the_full_lifecycle_in_order(tmp_path, good_runner, good_builder):
    clock = FakeClock()
    lab = FakeBaselineLab(clock, runner=good_runner)

    run_baseline_trial(variant="B", lab=lab, runs_dir=tmp_path, clock=clock, harness_commit="a" * 40, seed=SEED)

    assert lab.calls == ["docker_version", "sweep", "assert_clean", "check_disk", "up", "image_digests",
                         "preflight", "seed", "wait_ready", "verify_fresh_state", "measure_clock", "health",
                         "stop_attacker", "measure_clock", "target_exit_code", "stop_target", "collect_events",
                         "down"]
    assert any("sqlmap" in " ".join(argv) for argv in good_runner.calls)
    assert any("python3" in argv for argv in good_runner.calls)


def test_run_baseline_trial_failure_before_stages_skips_them(tmp_path, good_runner):
    clock = FakeClock()
    lab = FakeBaselineLab(clock, fail_at="preflight", runner=good_runner)

    run_dir = run_baseline_trial(variant="B", lab=lab, runs_dir=tmp_path, clock=clock,
                                 harness_commit="a" * 40, seed=SEED)

    result = json.loads((run_dir / "baseline_result.json").read_text())
    assert result["termination_reason"] == "harness_error"
    assert "preflight failed on purpose" in result["harness_error"]
    assert result["stage1"] is None
    assert result["stage2"] is None
    assert not any("sqlmap" in " ".join(argv) for argv in good_runner.calls)
    assert "down" in lab.calls        # teardown still ran


def test_run_baseline_trial_teardown_runs_even_when_a_stage_fails(tmp_path, monkeypatch):
    runner = make_runner({"inspect": (0, b"sha256:" + b"a" * 64, b""), "sqlmap": (1, b"", b"sqlmap failed")})
    clock = FakeClock()
    lab = FakeBaselineLab(clock, runner=runner)
    monkeypatch.setattr(run_baseline, "STAGE1_ARGV_BUILDER", GOOD_BUILDER)

    run_dir = run_baseline_trial(variant="B", lab=lab, runs_dir=tmp_path, clock=clock,
                                 harness_commit="a" * 40, seed=SEED)

    # stage 1's own non-zero exit is not raised as an error (sqlmap finding nothing is an ordinary
    # outcome, recorded in stage1's exit_code); the trial still completes and tears down.
    result = json.loads((run_dir / "baseline_result.json").read_text())
    assert result["stage1"]["exit_code"] == 1
    assert "down" in lab.calls


def test_run_baseline_trial_refuses_to_run_stage1_without_a_builder(tmp_path, good_runner, monkeypatch):
    clock = FakeClock()
    lab = FakeBaselineLab(clock, runner=good_runner)
    monkeypatch.setattr(run_baseline, "STAGE1_ARGV_BUILDER", None)   # the shipped default, set explicitly

    run_dir = run_baseline_trial(variant="B", lab=lab, runs_dir=tmp_path, clock=clock,
                                 harness_commit="a" * 40, seed=SEED)

    result = json.loads((run_dir / "baseline_result.json").read_text())
    assert result["termination_reason"] == "harness_error"
    assert "STAGE1_ARGV_BUILDER is not filled in" in result["harness_error"]
