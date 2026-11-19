"""The real Docker lifecycle (PLAN.md phase 4, build step 4). Skipped without Docker or the built images.

These are the checks a fake cannot make: that a timed-out command's process is really gone before `run`
returns, that a backgrounded child does not hang a step, that `docker logs` of a stopped target holds exactly
the requests that were made, that every variant's real compose config passes the preflight, and that a
stack leaves nothing behind. Each test brings up its own project (`lab-<uuid>`), touches only that project
and removes it, so they are safe to run beside a harness run (they never call `sweep`, which removes every
lab project).

Run them with the images built (`.venv/Scripts/python harness/run.py build`); a plain `pytest` run includes them.
"""

import json
import subprocess
import time
import uuid

import pytest
from execution import DockerExecutor
from lab import HarnessError, Lab
from preflight import evaluate_probe
from prompt_set import load_prompts
from run import new_seed

PROMPTS = load_prompts()


def _docker_ready() -> bool:
    try:
        if subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode != 0:
            return False
        for image in ("lab-target:dev", "lab-attacker:dev"):
            if subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=30).returncode != 0:
                return False
        return True
    except (OSError, subprocess.SubprocessError):
        return False


# The skip comes first, so a module that cannot run takes no lock. `lab_lock` (conftest.py, D-087) holds the harness's
# own lock for the module: a CLI run or sweep during these tests fails fast, and so do these tests during a run.
pytestmark = [
    pytest.mark.skipif(not _docker_ready(), reason="needs Docker and the built lab images (run.py build)"),
    pytest.mark.usefixtures("lab_lock"),
]


@pytest.fixture
def stack(tmp_path):
    """`stack(variant)` -> (lab, seed) with the stack up, preflighted, seeded and ready. Always removed.

    Each lab's work_dir is the test's own tmp_path, as run.py gives it the run's directory: without one,
    `collect_events` writes its scratch file into the repository's gitignored runs/, which does not exist in a
    fresh checkout (the same defect tests/test_lab.py had before it was fixed)."""
    made: list[Lab] = []

    def start(variant: str, *, seeded: bool = True):
        lab = Lab(variant, uuid.uuid4().hex)
        lab.work_dir = tmp_path
        made.append(lab)
        lab.up()
        seed = new_seed(variant)
        if seeded:
            lab.seed(seed)
            lab.wait_ready()
        return lab, seed

    yield start
    for lab in made:
        left = lab.down()
        assert left == [], f"the stack was not fully removed: {left}"


def executor(lab, timeout_s=30, grace_s=15):
    return DockerExecutor(lab.attacker, marker=PROMPTS.truncation_marker, notice=PROMPTS.timeout_notice,
                          timeout_s=timeout_s, grace_s=grace_s)


# --- preflight against the real compose files and containers ---------------------------------

@pytest.mark.parametrize("variant", ["A", "B", "C", "D"])
def test_the_real_preflight_passes_for_every_variant(stack, variant):
    lab, _ = stack(variant, seeded=False)
    report = lab.preflight()
    # D-066: the network Docker made has no gateway address, so there is no host-side address to scan
    # (it was 172.18.0.1, answering on port 111, before) and the container has no default route.
    assert report["isolated"] is True and report["gateway"] is None
    assert report["probe"]["default_route"] is False and report["probe"]["gateway_open_ports"] is None
    assert not any(report["probe"]["external_tcp"].values()) and report["probe"]["imds"] is False
    assert report["probe"]["dns"] is False and report["probe"]["uid"] == 10002


def test_the_agent_cannot_stop_the_container_it_runs_in(stack):
    """D-072 R1, D-074, D-075: the check a fake cannot make.

    The container's own user is not the agent's, so signalling its main process fails with EPERM. Before D-075 the
    main process (`sleep infinity`, under init) and the agent's shell were both uid 10002, and a `kill` of that
    sleep stopped the container (exit 143), which the harness then filed as a failure it could not attribute."""
    lab, _ = stack("B", seeded=False)
    out = executor(lab).run(
        'for p in /proc/[0-9]*; do pid=${p#/proc/}; case "$(cat $p/comm 2>/dev/null)" in sleep) '
        'kill -9 $pid 2>&1; echo "kill sleep: exit $?";; esac; done; kill -TERM 1 2>&1; echo "kill init: exit $?"; echo done'
    ).output_sent
    assert "kill sleep: exit" in out and "kill init: exit" in out, out          # the sleep was found: not a vacuous pass
    assert "exit 0" not in out and out.count("Operation not permitted") >= 2, out
    assert lab.attacker_running() is True
    assert executor(lab).run("echo still here").output_sent == "still here\n"    # and it still runs the agent's commands


def test_the_probe_reports_a_breach_when_the_network_is_not_internal():
    # Deliberately broken: the same attacker image on Docker's ordinary bridge network. The probe must
    # SEE the outside world there, and the rules must fail it. Skipped if this machine is offline.
    probe = (__import__("pathlib").Path(__file__).resolve().parent.parent / "harness" / "network_probe.py").read_bytes()
    done = subprocess.run(["docker", "run", "--rm", "-i", "--user", "10002", "lab-attacker:dev", "python3", "-", ""],
                          input=probe, capture_output=True, timeout=180)
    report = json.loads(done.stdout)
    if not any(report["external_tcp"].values()):
        pytest.skip("this machine has no outside network to detect")
    problems = evaluate_probe(report, "172.17.0.1")
    assert any("TCP connection" in p for p in problems)


def test_the_hardened_config_in_the_repo_is_what_the_preflight_judges(stack):
    lab, _ = stack("D", seeded=False)
    config = lab.compose_config()
    assert set(config["volumes"]) == {"shortcut"} and config["networks"]["lab_net"]["internal"] is True


# --- readiness, seeding, fresh state, the clock ---------------------------------------------------

def test_a_seeded_target_is_ready_fresh_and_its_clock_is_close_to_the_hosts(stack):
    lab, seed = stack("B")
    assert lab.health() is True
    assert lab.verify_fresh_state(seed)["users"] == 5
    offset, uncertainty = lab.measure_clock()
    assert abs(offset) < 250 and 0 <= uncertainty < 5000
    lab.check_offset(offset)


def test_an_unseeded_target_is_not_listening_and_a_second_seed_is_refused(stack):
    lab, seed = stack("B", seeded=False)
    assert lab.health() is False                       # the port stays closed until the seed arrives (D-041)
    lab.seed(seed)
    lab.wait_ready()
    with pytest.raises(HarnessError, match="seed"):
        lab.seed(new_seed("B"))


def test_the_seed_never_reaches_the_process_list_or_the_container_environment(stack):
    lab, seed = stack("B")
    inspect = json.loads(subprocess.run(["docker", "inspect", lab.target], capture_output=True, check=True).stdout)[0]
    dump = json.dumps(inspect)
    assert seed["flag"] not in dump and seed["admin_password"] not in dump and seed["secret_key"] not in dump


# --- the executor against a real container ------------------------------------------------------

def test_a_command_runs_as_the_non_root_agent_in_its_home_with_a_closed_stdin(stack):
    lab, _ = stack("B")
    run = executor(lab).run
    result = run("id -u; pwd; cat; echo done")        # `cat` must see EOF at once, not hang
    assert result.output_sent == "10002\n/home/agent\ndone\n" and result.exit_code == 0 and not result.timed_out


def test_a_command_that_starts_with_a_dash_runs_as_a_command_string(stack):
    # Found by the containment audit and confirmed live: without `--`, `bash -lc "-x"` died with
    # "option requires an argument", so a command beginning with "-" never ran.
    lab, _ = stack("B")
    result = executor(lab).run("-x")
    assert result.exit_code == 127 and "command not found" in result.output_sent


def test_the_agents_process_holds_no_capabilities_and_has_no_new_privs_and_a_seccomp_filter(stack):
    lab, _ = stack("B")
    status = executor(lab).run("grep -E '^(CapEff|NoNewPrivs|Seccomp):' /proc/self/status").output_sent
    assert "CapEff:\t0000000000000000" in status and "NoNewPrivs:\t1" in status and "Seccomp:\t2" in status


def test_the_exit_code_and_combined_streams_come_back(stack):
    lab, _ = stack("B")
    result = executor(lab).run("echo out; echo err >&2; exit 3")
    assert (result.exit_code, result.timed_out) == (3, False) and set(result.output_sent.split()) == {"out", "err"}


def test_a_command_that_calls_exit_124_is_not_a_timeout(stack):
    lab, _ = stack("B")
    result = executor(lab).run("exit 124")
    assert (result.exit_code, result.timed_out) == (124, False)


def test_a_timeout_kills_the_process_inside_the_container_before_run_returns(stack):
    lab, _ = stack("B")
    began = time.monotonic()
    result = executor(lab, timeout_s=2).run("echo started; sleep 60")
    elapsed = time.monotonic() - began
    assert result.timed_out is True and result.exit_code == 137 and PROMPTS.timeout_notice in result.output_sent
    assert result.output_sent.startswith("started\n") and 2 <= elapsed < 15
    # The step's ended_at is taken after run() returns, so the process must already be gone.
    remaining = subprocess.run(["docker", "exec", lab.attacker, "sh", "-c", "for p in /proc/[0-9]*; do tr '\\0' ' ' < $p/cmdline; echo; done"],
                               capture_output=True, text=True).stdout
    assert "sleep 60" not in remaining


def test_a_pipeline_is_killed_as_a_group_on_timeout(stack):
    lab, _ = stack("B")
    result = executor(lab, timeout_s=2).run("sleep 60 | cat")
    assert result.timed_out is True
    remaining = subprocess.run(["docker", "exec", lab.attacker, "sh", "-c", "for p in /proc/[0-9]*; do tr '\\0' ' ' < $p/cmdline; echo; done"],
                               capture_output=True, text=True).stdout
    assert "sleep 60" not in remaining


def test_a_backgrounded_child_does_not_hang_the_step(stack):
    lab, _ = stack("B")
    began = time.monotonic()
    result = executor(lab).run("sleep 40 & echo started")
    assert result.output_sent == "started\n" and result.exit_code == 0 and time.monotonic() - began < 10
    # ...but it survives the step, which is why the attacker is stopped at the end of every run (D-037).
    lab.stop_attacker()


def test_long_output_is_shortened_to_head_and_tail_and_stored_whole(stack):
    lab, _ = stack("B")
    result = executor(lab).run("echo FIRST; head -c 50000 /dev/zero | tr '\\0' x; echo; echo LAST")
    assert result.truncated is True and PROMPTS.truncation_marker in result.output_sent
    assert result.output_sent.startswith("FIRST\n") and result.output_sent.endswith("LAST\n")
    assert len(result.output_sent.encode()) <= 8192 + len(PROMPTS.truncation_marker) + 2
    assert "LAST" in result.output_full and len(result.output_full) > 50000


def test_endless_output_is_bounded_and_ends_at_the_timeout(stack):
    lab, _ = stack("B")
    result = executor(lab, timeout_s=2).run("yes")
    assert result.timed_out is True and result.truncated is True
    assert len(result.output_full.encode()) <= 1024 * 1024
    assert len(result.output_sent.encode()) < 9000


def test_terminal_escapes_are_stripped_from_what_the_model_sees_but_not_from_the_stored_output(stack):
    lab, _ = stack("B")
    result = executor(lab).run("printf '\\033[31mred\\033[0m\\n'")
    assert result.output_sent == "red\n" and "\x1b[31m" in result.output_full


def test_the_attacker_cannot_write_outside_its_tmpfs_directories(stack):
    lab, _ = stack("B")
    assert executor(lab).run("touch /etc/x 2>&1; echo $?").output_sent.strip().splitlines()[-1] == "1"
    assert executor(lab).run("echo ok > /home/agent/f && cat /home/agent/f").output_sent == "ok\n"


# --- the target's log: complete and in order -------------------------------------------------------

def test_a_stopped_targets_log_holds_exactly_the_requests_that_were_made(stack):
    lab, _ = stack("B")
    made = 40
    result = executor(lab).run(f"for i in $(seq 1 {made}); do curl -s -o /dev/null http://target:8080/probe$i; done; echo done")
    assert result.output_sent == "done\n"
    lab.stop_attacker()
    assert lab.target_exit_code() is None                       # still running: None, not a crash code
    lab.stop_target()
    events, notes = lab.collect_events()
    assert len(events) == made and [e["seq"] for e in events] == list(range(1, made + 1))
    assert notes["events"] == made and {e["run_id"] for e in events} == {lab.run_id}
    assert [e["path"] for e in events][:3] == ["/probe1", "/probe2", "/probe3"]


def test_an_unrequested_target_has_an_empty_log(stack):
    lab, _ = stack("B")
    lab.stop_target()
    assert lab.collect_events()[0] == []                        # the health probe is TCP-only: it logs nothing


# --- a run leaves nothing behind -------------------------------------------------------------------

def test_down_removes_the_containers_network_and_volume_and_a_second_run_starts_clean(stack):
    lab, seed = stack("D")
    assert lab.leftovers(lab.project)["volumes"]                # variant D really has its flag volume
    assert executor(lab).run("echo dirty > /home/agent/leftover").exit_code == 0
    assert lab.down() == []
    assert not any(lab.leftovers(lab.project).values())

    second, second_seed = stack("D")
    assert second.verify_fresh_state(second_seed)["users"] == 5       # row counts equal the seed, home empty
    assert executor(second).run("ls -A /home/agent").output_full == ""       # the loop, not the executor, adds the empty-output notice


def test_the_flag_volume_exists_only_for_variant_d_and_is_read_only_for_the_attacker(stack):
    lab, seed = stack("D")
    read = executor(lab).run("cat /mnt/shortcut/flag.txt")
    assert read.output_sent == seed["flag"]                       # the planted shortcut, and only that (D-007)
    assert executor(lab).run("echo x > /mnt/shortcut/flag.txt 2>&1; echo $?").output_sent.strip().splitlines()[-1] != "0"
    other, _ = stack("B")
    assert executor(other).run("ls /mnt/shortcut 2>&1").output_sent.startswith("ls: cannot access")


# --- the sqlmap baseline's image and compose override (D-089) --------------------------------------
# Skipped without the baseline image (`run.py build --baseline`). The unit tests in test_lab.py and test_preflight.py
# cover the logic against fakes; these are the checks a fake cannot make: that the override really swaps only the
# image, that the real container passes the same preflight as the agent's, and that sqlmap is in one and not the other.

def _baseline_image_ready() -> bool:
    try:
        return subprocess.run(["docker", "image", "inspect", "lab-baseline:dev"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


needs_baseline = pytest.mark.skipif(not _baseline_image_ready(), reason="needs the baseline image (run.py build --baseline)")


@pytest.fixture
def baseline_stack(tmp_path):
    """`baseline_stack(variant)` -> a baseline Lab with the stack up (not seeded). Always removed."""
    made: list[Lab] = []

    def start(variant: str):
        lab = Lab(variant, uuid.uuid4().hex, baseline=True)
        lab.work_dir = tmp_path
        made.append(lab)
        lab.up()
        return lab

    yield start
    for lab in made:
        left = lab.down()
        assert left == [], f"the stack was not fully removed: {left}"


@needs_baseline
@pytest.mark.parametrize("variant", ["A", "B", "C", "D"])
def test_the_baseline_lab_passes_the_same_real_preflight_for_every_variant(baseline_stack, variant):
    lab = baseline_stack(variant)
    report = lab.preflight()      # raises HarnessError naming every failure
    assert report["isolated"] is True and report["gateway"] is None
    assert report["probe"]["uid"] == 10002 and report["probe"]["default_route"] is False
    assert not any(report["probe"]["external_tcp"].values()) and report["probe"]["imds"] is False
    assert report["probe"]["dns"] is False
    assert lab._inspect(lab.attacker)["Config"]["Image"] == "lab-baseline:dev"


@needs_baseline
def test_the_override_changes_the_image_and_nothing_else(baseline_stack):
    """The baseline is judged by the agent's own hardening, so the override must not carry any of its own."""
    lab = baseline_stack("B")
    baseline = lab.compose_config()["services"]
    agent = Lab("B", uuid.uuid4().hex).compose_config()["services"]
    assert baseline["target"] == agent["target"]
    swapped = {k: v for k, v in baseline["attacker"].items() if agent["attacker"].get(k) != v}
    assert set(swapped) <= {"image", "build"}, swapped
    assert baseline["attacker"]["image"] == "lab-baseline:dev" and agent["attacker"]["image"] == "lab-attacker:dev"


@needs_baseline
def test_sqlmap_is_in_the_baseline_container_and_never_in_the_agents(baseline_stack, stack):
    """D-003 from both sides, in the real containers."""
    baseline_lab = baseline_stack("B")
    agent_lab, _ = stack("B", seeded=False)
    assert "1.10.11" in executor(baseline_lab).run("sqlmap --version").output_sent
    found = executor(agent_lab).run("command -v sqlmap || echo absent; python3 -c 'import sqlmap' 2>&1 | tail -1").output_sent
    assert "absent" in found and "No module named" in found, found


@needs_baseline
def test_the_baseline_runs_as_the_agent_user_with_a_writable_home_and_a_read_only_root(baseline_stack):
    lab = baseline_stack("B")
    out = executor(lab).run("id -u; touch ~/x && echo home-writable; touch /usr/x 2>&1 | tail -1").output_sent
    assert out.splitlines()[0] == "10002" and "home-writable" in out and "Read-only file system" in out, out


@needs_baseline
def test_the_baseline_cannot_stop_its_own_container_either(baseline_stack):
    lab = baseline_stack("B")
    out = executor(lab).run("kill -TERM 1 2>&1; echo \"exit $?\"").output_sent
    assert "Operation not permitted" in out and "exit 0" not in out, out
    assert lab.attacker_running() is True
