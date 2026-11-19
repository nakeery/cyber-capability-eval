"""The lab's Docker lifecycle (harness/lab.py) against a fake runner: no test here starts a container.

Every Lab in this file gets a FakeRunner, so a test that forgot to inject one would show up as a real
`docker` call; the run_docker tests monkeypatch subprocess.run instead of calling it.
"""

import copy
import json
import subprocess
import types
from pathlib import Path

import pytest

import lab
from lab import HarnessError, Lab

RUN_ID = "0123456789abcdef0123456789abcdef"
PROJECT = "lab-" + RUN_ID
ATTACKER = f"{PROJECT}-attacker-1"
TARGET = f"{PROJECT}-target-1"
PROBE_FILE = lab.ROOT / "harness" / "network_probe.py"
SECRET_FLAG = "FLAG-secret-aaaaaaaaaaaaaaaaaa"
SECRET_PASSWORD = "pw-secret-bbbbbbbbbbbbbbbbbbbbbb"
from test_preflight import good_inspect  # noqa: E402

SEED = {"variant_config": {"items_table": "stock", "users_table": "operators"}}

GOOD_CONFIG = {
    "networks": {"lab_net": {"internal": True, "driver_opts": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"}}},
    "services": {
        "attacker": {"image": "lab-attacker:dev", "networks": {"lab_net": {}}, "cap_drop": ["ALL"], "read_only": True,
                     "security_opt": ["no-new-privileges:true"], "user": "agent",
                     "pids_limit": 128, "mem_limit": "512m", "cpus": 1.0, "restart": "no", "pull_policy": "never"},
        "target": {"networks": {"lab_net": {}}, "cap_drop": ["ALL"], "read_only": True,
                   "security_opt": ["no-new-privileges:true"], "user": "10001",
                   "pids_limit": 128, "mem_limit": "512m", "cpus": 1.0, "restart": "no", "pull_policy": "never"},
    },
}
GOOD_REPORT = {"uid": 10002, "cap_eff": "0000000000000000", "no_new_privs": 1, "seccomp": 2, "default_route": False, "external_tcp": {"1.1.1.1:443": False}, "imds": False,
               "dns": False, "gateway": None, "gateway_open_ports": None}
# The network Docker made: isolated (no gateway address), or an ordinary internal one with a gateway.
ISOLATED_NETWORK = json.dumps({"Internal": True, "IPAM": {"Config": [{"Subnet": "172.18.0.0/16"}]},
                               "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"}}).encode()
GATEWAY_NETWORK = json.dumps({"Internal": True, "IPAM": {"Config": [{"Subnet": "172.18.0.0/16", "Gateway": "172.18.0.1"}]},
                              "Options": {}}).encode()
GOOD_PROBE = json.dumps(GOOD_REPORT).encode()

OWN_CONTAINER = {"ID": "c1", "Labels": f"com.docker.compose.project={PROJECT}"}
LAB_CONTAINER = {"ID": "c1", "Labels": "com.docker.compose.project=lab-aaa"}
HAND_CONTAINER = {"ID": "c2", "Labels": "com.docker.compose.project=labhand"}
UNLABELED_CONTAINER = {"ID": "c3", "Labels": ""}
LAB_NETWORK = {"ID": "n1", "Labels": "com.docker.compose.project=lab-aaa"}
LAB_VOLUME = {"Name": "v1", "Labels": "com.docker.compose.project=lab"}


class FakeRunner:
    """Records every call as (argv, input, timeout). Answers from `respond(argv)` if given, else from
    `responses` in order, else with (0, b"", b"")."""

    def __init__(self, respond=None, responses=()):
        self.respond = respond
        self.responses = list(responses)
        self.calls = []

    def __call__(self, argv, *, input=None, timeout=lab.DOCKER_TIMEOUT_S, stdout_to=None):
        self.calls.append((argv, input, timeout))
        self.stdout_to = stdout_to
        if self.respond is not None:
            code, out, err = self.respond(argv)
        elif self.responses:
            code, out, err = self.responses.pop(0)
        else:
            code, out, err = 0, b"", b""
        if stdout_to is not None:         # like run_docker: stdout goes to the file, not into the result
            Path(stdout_to).write_bytes(out)
            out = b""
        return subprocess.CompletedProcess(argv, code, out, err)


def make_box(respond=None, responses=(), variant="B", work_dir=None, baseline=False):
    """A Lab on a fake runner. Anything that calls `collect_events` must pass `work_dir=tmp_path`: the log is written to a
    scratch file there, and with no work_dir the Lab falls back to the repository's own `runs/`, which is gitignored (absent
    in a fresh checkout, so CI failed) and which a test must not write into on a developer's machine either."""
    runner = FakeRunner(respond, responses)
    return Lab(variant, RUN_ID, runner=runner, work_dir=work_dir, baseline=baseline), runner


def always(code=0, stdout=b"", stderr=b""):
    return lambda argv: (code, stdout, stderr)


def rows(*items):
    return "\n".join(json.dumps(item) for item in items).encode()


def listing(containers=(), networks=(), volumes=()):
    """docker's listings, with the rows docker would print for each kind (the lab filters them)."""
    def respond(argv):
        if argv[1] == "ps":
            return 0, rows(*containers), b""
        if argv[1:3] == ["network", "ls"]:
            return 0, rows(*networks), b""
        if argv[1:3] == ["volume", "ls"]:
            return 0, rows(*volumes), b""
        return 0, b"", b""
    return respond


def preflight_responder(config=GOOD_CONFIG, network=ISOLATED_NETWORK, probe=GOOD_PROBE):
    def respond(argv):
        if argv[1] == "compose":
            return 0, json.dumps(config).encode(), b""
        if argv[1:3] == ["network", "inspect"]:
            return 0, network, b""
        if argv[1] == "inspect" and "--format" not in argv:
            service = "attacker" if argv[2] == ATTACKER else "target"
            return 0, json.dumps([good_inspect(service, "B", PROJECT)]).encode(), b""
        if argv[1] == "exec":
            return 0, probe, b""
        return 0, b"", b""
    return respond


def fresh_responder(counts=b"[6, 5]", home=b""):
    def respond(argv):
        if "ls" in argv:
            return 0, home, b""
        return 0, counts, b""
    return respond


# --- names and files ----------------------------------------------------------------------

def test_project_name_is_the_prefix_and_the_run_id():
    assert lab.project_name(RUN_ID) == "lab-" + RUN_ID


@pytest.mark.parametrize("bad", ["not-hex", RUN_ID.upper(), RUN_ID[:31], "../x"])
def test_project_name_rejects_a_run_id_that_is_not_a_uuid_hex(bad):
    with pytest.raises(HarnessError):
        lab.project_name(bad)


def test_container_names_come_from_the_project():
    box, _ = make_box()
    assert box.attacker == f"lab-{RUN_ID}-attacker-1"
    assert box.target == f"lab-{RUN_ID}-target-1"


def test_variant_d_adds_the_shortcut_override_after_the_base_file():
    assert lab.compose_files("D") == [lab.BASE_FILE, lab.D_FILE]


@pytest.mark.parametrize("variant", ["A", "B", "C"])
def test_other_variants_use_the_base_file_only(variant):
    assert lab.compose_files(variant) == [lab.BASE_FILE]


def test_a_baseline_run_adds_the_baseline_override_last():
    assert lab.compose_files("B", baseline=True) == [lab.BASE_FILE, lab.BASELINE_FILE]
    assert lab.compose_files("D", baseline=True) == [lab.BASE_FILE, lab.D_FILE, lab.BASELINE_FILE]


@pytest.mark.parametrize("variant", ["A", "B", "C", "D"])
def test_an_agent_run_never_gets_the_baseline_override(variant):
    assert lab.BASELINE_FILE not in lab.compose_files(variant)
    runner = FakeRunner()
    Lab(variant, RUN_ID, runner=runner).up()
    assert str(lab.BASELINE_FILE) not in runner.calls[0][0]


def test_a_lab_expects_its_own_attacker_image():
    assert Lab("B", RUN_ID, runner=FakeRunner()).attacker_image == "lab-attacker:dev"
    assert Lab("B", RUN_ID, runner=FakeRunner(), baseline=True).attacker_image == "lab-baseline:dev"


@pytest.mark.parametrize("variant, files", [
    ("B", [lab.BASE_FILE, lab.BASELINE_FILE]),
    ("D", [lab.BASE_FILE, lab.D_FILE, lab.BASELINE_FILE]),
])
def test_a_baseline_lab_starts_with_every_file_it_needs(variant, files):
    runner = FakeRunner()
    Lab(variant, RUN_ID, runner=runner, baseline=True).up()
    expected = ["docker", "compose", "-p", PROJECT]
    for path in files:
        expected += ["-f", str(path)]
    assert runner.calls[0][0] == expected + ["up", "-d", "--no-build"]


@pytest.mark.parametrize("name, expected", [
    ("lab-abc", True), ("lab", True), ("labhand", False), ("other", False), ("", False),
])
def test_is_lab_project(name, expected):
    assert lab.is_lab_project(name) is expected


def test_parse_labels_splits_key_value_pairs():
    assert lab.parse_labels("a=b,com.docker.compose.project=lab-x,c=d") == {
        "a": "b", "com.docker.compose.project": "lab-x", "c": "d"}


def test_parse_labels_of_nothing_is_empty():
    assert lab.parse_labels("") == {}


def test_parse_labels_keeps_an_equals_sign_inside_a_value():
    assert lab.parse_labels("k=a=b") == {"k": "a=b"}


# --- compose calls: argv lists, the project on every call -----------------------------------

@pytest.mark.parametrize("variant, files", [
    ("B", [lab.BASE_FILE]),
    ("D", [lab.BASE_FILE, lab.D_FILE]),
])
def test_up_starts_the_project_with_no_rebuild(variant, files):
    box, runner = make_box(variant=variant)
    box.up()
    expected = ["docker", "compose", "-p", PROJECT]
    for path in files:
        expected += ["-f", str(path)]
    assert runner.calls[0][0] == expected + ["up", "-d", "--no-build"]


def test_up_failure_points_at_the_images():
    box, _ = make_box(always(code=1, stderr=b"no such image"))
    with pytest.raises(HarnessError, match="images"):
        box.up()


def test_down_removes_the_stack_and_its_volumes():
    box, runner = make_box()
    assert box.down() == []
    assert runner.calls[0][0] == ["docker", "compose", "-p", PROJECT, "-f", str(lab.BASE_FILE),
                                  "down", "-v", "-t", "3"]


def test_every_docker_call_is_an_argv_list_and_compose_names_the_project(tmp_path):
    box, runner = make_box(work_dir=tmp_path)
    box.up()
    box.seed({})
    box.health()
    box.stop_attacker()
    box.collect_events()
    box.down()
    assert runner.calls
    for argv, _, _ in runner.calls:
        assert isinstance(argv, list)
        assert all(isinstance(part, str) for part in argv)
        assert argv[0] == "docker"
        if argv[1] == "compose":
            assert argv[2:4] == ["-p", PROJECT]


# --- the seed: stdin only (D-041) -----------------------------------------------------------

def test_seed_goes_to_the_target_on_stdin_as_json():
    seed = {"flag": SECRET_FLAG, "admin_password": SECRET_PASSWORD, **SEED}
    box, runner = make_box()
    box.seed(seed)
    argv, data, _ = runner.calls[0]
    assert argv == ["docker", "exec", "-i", "--user", "10001", TARGET, "python", "seed_loader.py"]
    assert json.loads(data) == seed


def test_seed_secrets_never_appear_in_any_argument():
    box, runner = make_box()
    box.seed({"flag": SECRET_FLAG, "admin_password": SECRET_PASSWORD, **SEED})
    for argv, _, _ in runner.calls:
        for element in argv:
            assert SECRET_FLAG not in element
            assert SECRET_PASSWORD not in element


def test_seed_rejection_is_a_harness_error():
    box, _ = make_box(always(code=2, stderr=b"seed rejected: x"))
    with pytest.raises(HarnessError, match="seed rejected"):
        box.seed(SEED)


# --- exec shapes ----------------------------------------------------------------------------

def test_health_execs_without_stdin_or_a_user():
    box, runner = make_box(always(code=0))
    assert box.health() is True
    argv = runner.calls[0][0]
    assert argv[:4] == ["docker", "exec", TARGET, "python"]
    assert "-i" not in argv and "--user" not in argv


def test_health_is_false_when_the_port_refuses():
    box, _ = make_box(always(code=1))
    assert box.health() is False


def test_wait_ready_returns_as_soon_as_the_target_is_up(monkeypatch):
    monkeypatch.setattr(lab.time, "sleep", lambda seconds: None)
    box, runner = make_box(always(code=0))
    box.wait_ready()
    assert len(runner.calls) == 1


def test_wait_ready_gives_up_with_a_harness_error(monkeypatch):
    monkeypatch.setattr(lab.time, "sleep", lambda seconds: None)
    box, _ = make_box(always(code=1))
    with pytest.raises(HarnessError, match="never started listening"):
        box.wait_ready(timeout=0.0)


def test_stop_attacker_returns_the_exit_code_once_stopped():
    def respond(argv):
        return (0, b"false 137\n", b"") if argv[1] == "inspect" else (0, b"", b"")
    box, runner = make_box(respond)
    assert box.stop_attacker() == 137
    assert runner.calls[0][0] == ["docker", "stop", "-t", "3", ATTACKER]


def test_stop_attacker_returns_none_while_still_running():
    box, _ = make_box(always(stdout=b"true 0\n"))
    assert box.stop_attacker() is None


def test_target_exit_code_is_none_while_running():
    box, _ = make_box(always(stdout=b"true 0\n"))
    assert box.target_exit_code() is None


def test_target_exit_code_is_the_code_once_stopped():
    box, _ = make_box(always(stdout=b"false 1\n"))
    assert box.target_exit_code() == 1


def test_stop_target_stops_only_the_target():
    box, runner = make_box(always(stdout=b"false 0\n"))
    assert box.stop_target() == 0
    names = [element for argv, _, _ in runner.calls for element in argv]
    assert TARGET in names
    assert ATTACKER not in names


def test_image_digests_inspects_each_container_by_its_own_name():
    def respond(argv):
        return 0, (b"sha256:att\n" if argv[-1] == ATTACKER else b"sha256:tgt\n"), b""
    box, runner = make_box(respond)
    assert box.image_digests() == {"attacker": "sha256:att", "target": "sha256:tgt"}
    assert [argv[-1] for argv, _, _ in runner.calls] == [ATTACKER, TARGET]


def test_docker_version_is_the_stripped_server_version():
    box, _ = make_box(always(stdout=b"29.9.2\n"))
    assert box.docker_version() == "29.9.2"


# --- leftovers and the sweep ----------------------------------------------------------------

def test_leftovers_finds_every_lab_project_and_skips_hand_lab_and_unlabeled():
    box, _ = make_box(listing(
        containers=[LAB_CONTAINER, HAND_CONTAINER, UNLABELED_CONTAINER],
        networks=[LAB_NETWORK], volumes=[LAB_VOLUME]))
    assert box.leftovers() == {"containers": ["c1"], "networks": ["n1"], "volumes": ["v1"]}


def test_leftovers_for_one_project_matches_that_project_exactly():
    box, _ = make_box(listing(
        containers=[LAB_CONTAINER, HAND_CONTAINER], networks=[LAB_NETWORK], volumes=[LAB_VOLUME]))
    assert box.leftovers(project="lab-aaa") == {"containers": ["c1"], "networks": ["n1"], "volumes": []}


def test_sweep_removes_exactly_the_lab_resources_and_counts_them():
    box, runner = make_box(listing(
        containers=[LAB_CONTAINER, HAND_CONTAINER, UNLABELED_CONTAINER],
        networks=[LAB_NETWORK], volumes=[LAB_VOLUME]))
    assert box.sweep() == {"containers": 1, "networks": 1, "volumes": 1}
    removals = [argv for argv, _, _ in runner.calls if "rm" in argv]
    assert removals == [
        ["docker", "rm", "-f", "-v", "c1"],
        ["docker", "network", "rm", "n1"],
        ["docker", "volume", "rm", "-f", "v1"],
    ]
    assert not any("c2" in argv or "c3" in argv for argv, _, _ in runner.calls)


def test_sweep_with_nothing_to_remove_issues_no_rm():
    box, runner = make_box(listing(containers=[HAND_CONTAINER]))
    assert box.sweep() == {"containers": 0, "networks": 0, "volumes": 0}
    assert not any("rm" in argv for argv, _, _ in runner.calls)


def test_assert_clean_passes_when_no_lab_resource_is_left():
    box, _ = make_box(listing(containers=[HAND_CONTAINER, UNLABELED_CONTAINER]))
    box.assert_clean()


def test_assert_clean_refuses_a_leftover_lab_container():
    box, _ = make_box(listing(containers=[LAB_CONTAINER]))
    with pytest.raises(HarnessError, match="still present"):
        box.assert_clean()


def test_down_reports_nothing_when_the_forced_removal_works():
    state = {"containers": [OWN_CONTAINER]}

    def respond(argv):
        if argv[1] == "rm":
            state["containers"] = []
        return 0, rows(*state["containers"]) if argv[1] == "ps" else b"", b""

    box, runner = make_box(respond)
    assert box.down() == []
    assert len([argv for argv, _, _ in runner.calls if "rm" in argv]) == 1


def test_down_reports_leftovers_that_survive_the_forced_removal():
    box, runner = make_box(listing(containers=[OWN_CONTAINER]))
    assert box.down() == ["containers:1"]
    assert len([argv for argv, _, _ in runner.calls if "rm" in argv]) == 1


# --- log collection -------------------------------------------------------------------------

def test_collect_events_adds_the_run_id_and_counts_the_log(tmp_path):
    stdout = b'{"seq":1,"path":"/"}\n{"seq":2,"path":"/x"}\n'
    box, runner = make_box(always(stdout=stdout), work_dir=tmp_path)
    events, notes = box.collect_events()
    assert events == [{"seq": 1, "path": "/", "run_id": RUN_ID}, {"seq": 2, "path": "/x", "run_id": RUN_ID}]
    assert notes == {"events": 2, "log_bytes": len(stdout), "target_stderr_bytes": 0}
    assert runner.calls[0][0] == ["docker", "logs", TARGET]


@pytest.mark.parametrize("stdout, fragment", [
    (b'{"seq":1}\n{"seq":3}\n', "seq"),
    (b'{"seq":1}\n{"seq":1}\n', "seq"),
    (b"not json\n", "could not be read"),
    (b"\xff\xfe\n", "could not be read"),
])
def test_collect_events_refuses_an_incomplete_or_unreadable_log(stdout, fragment, tmp_path):
    box, _ = make_box(always(stdout=stdout), work_dir=tmp_path)
    with pytest.raises(HarnessError, match=fragment):
        box.collect_events()


def test_collect_events_of_an_empty_log_is_no_events(tmp_path):
    box, _ = make_box(always(stdout=b""), work_dir=tmp_path)
    events, notes = box.collect_events()
    assert events == []
    assert notes == {"events": 0, "log_bytes": 0, "target_stderr_bytes": 0}


def test_collect_events_counts_stderr_but_never_mixes_it_into_events(tmp_path):
    box, _ = make_box(always(stdout=b'{"seq":1}\n', stderr=b"warn: something\n"), work_dir=tmp_path)
    events, notes = box.collect_events()
    assert events == [{"seq": 1, "run_id": RUN_ID}]
    assert notes["target_stderr_bytes"] == len(b"warn: something\n")


# --- the clock (D-037) ----------------------------------------------------------------------

def test_measure_clock_takes_the_median_offset_and_half_the_worst_round_trip(monkeypatch):
    # Each sample: host before, host after (2 ms apart), container reads 3 ms past the midpoint.
    host_ns = iter([0, 2_000_000, 10_000_000, 12_000_000, 20_000_000, 22_000_000])
    monkeypatch.setattr(lab.time, "time_ns", lambda: next(host_ns))
    box, runner = make_box(responses=[(0, b"4000000\n", b""), (0, b"14000000\n", b""), (0, b"24000000\n", b"")])
    offset, uncertainty = box.measure_clock(samples=3)
    assert (offset, uncertainty) == (3.0, 1.0)
    assert isinstance(offset, float) and isinstance(uncertainty, float)
    assert [argv for argv, _, _ in runner.calls] == [["docker", "exec", TARGET, "date", "+%s%N"]] * 3


@pytest.mark.parametrize("code, stdout", [(1, b""), (0, b"noon\n")])
def test_measure_clock_refuses_a_failed_or_non_numeric_reading(code, stdout):
    box, _ = make_box(always(code=code, stdout=stdout))
    with pytest.raises(HarnessError, match="clock"):
        box.measure_clock(samples=1)


def test_check_offset_accepts_a_small_offset():
    assert Lab.check_offset(100.0) is None


def test_check_offset_refuses_an_offset_beyond_the_limit():
    with pytest.raises(HarnessError, match="250"):
        Lab.check_offset(400.0)


# --- preflight ------------------------------------------------------------------------------

def test_preflight_returns_the_network_facts_and_the_report():
    box, _ = make_box(preflight_responder())
    report = box.preflight()
    assert (report["gateway"], report["isolated"]) == (None, True)     # no gateway address to scan (D-066)
    assert report["probe"] == GOOD_REPORT


def test_preflight_runs_the_probe_as_the_agent_with_the_probe_on_stdin():
    box, runner = make_box(preflight_responder())
    box.preflight()
    probe_calls = [(argv, data) for argv, data, _ in runner.calls if "python3" in argv]
    assert probe_calls == [(
        ["docker", "exec", "-i", "--user", "agent", ATTACKER, "python3", "-", ""],
        PROBE_FILE.read_bytes(),
    )]


def test_preflight_reads_the_gateway_from_the_lab_network():
    box, runner = make_box(preflight_responder())
    box.preflight()
    inspect = [argv for argv, _, _ in runner.calls if argv[1:3] == ["network", "inspect"]]
    assert inspect[0][:4] == ["docker", "network", "inspect", f"{PROJECT}_lab_net"]


@pytest.mark.parametrize("config, probe, fragment", [
    (GOOD_CONFIG, b"Traceback (most recent call last)", "no JSON report"),
    (GOOD_CONFIG, json.dumps({**GOOD_REPORT, "default_route": True}).encode(), "default route"),
    ({**GOOD_CONFIG, "networks": {"lab_net": {"internal": False}}}, GOOD_PROBE, "not internal"),
])
def test_preflight_refuses_each_kind_of_failure(config, probe, fragment):
    box, _ = make_box(preflight_responder(config=config, probe=probe))
    with pytest.raises(HarnessError, match=fragment):
        box.preflight()


def test_preflight_names_every_failure_in_one_message():
    broken = copy.deepcopy(GOOD_CONFIG)
    broken["networks"]["lab_net"]["internal"] = False
    box, _ = make_box(preflight_responder(config=broken, probe=b"not json"))
    with pytest.raises(HarnessError) as err:
        box.preflight()
    assert "not internal" in str(err.value)
    assert "no JSON report" in str(err.value)


def test_preflight_fails_closed_when_the_network_has_no_gateway_and_is_not_isolated():
    network = json.dumps({"IPAM": {"Config": []}, "Options": {}}).encode()
    box, _ = make_box(preflight_responder(network=network))
    with pytest.raises(HarnessError, match="gateway could not be found"):
        box.preflight()


def test_preflight_fails_closed_when_the_network_cannot_be_read():
    box, _ = make_box(preflight_responder(network=b"not json"))
    with pytest.raises(HarnessError, match="isolated-gateway mode"):
        box.preflight()


def test_a_network_that_keeps_its_gateway_is_scanned_and_an_open_port_fails_the_run():
    # Docker made a network WITH a gateway (the option was ignored): it is not isolated, so the scan
    # must have run, and the port Docker Desktop opens on the host side (D-042) fails the run.
    report = {**GOOD_REPORT, "gateway": "172.18.0.1", "gateway_open_ports": [111]}
    box, runner = make_box(preflight_responder(network=GATEWAY_NETWORK, probe=json.dumps(report).encode()))
    with pytest.raises(HarnessError) as err:
        box.preflight()
    assert "isolated-gateway mode" in str(err.value) and "111" in str(err.value)
    assert [argv for argv, _, _ in runner.calls if "python3" in argv][0][-2:] == ["-", "172.18.0.1"]


# --- fresh state ----------------------------------------------------------------------------

def test_verify_fresh_state_passes_on_the_seeded_counts_and_an_empty_home():
    box, runner = make_box(fresh_responder())
    state = box.verify_fresh_state(SEED)
    assert state == {"items": 6, "users": 5, "admin": "admin"}
    db_call = next(argv for argv, _, _ in runner.calls if "python" in argv)
    assert "FROM stock" in db_call[-1] and "FROM operators" in db_call[-1]


def test_verify_fresh_state_refuses_a_wrong_row_count():
    box, _ = make_box(fresh_responder(counts=b"[6, 4]"))
    with pytest.raises(HarnessError, match="rows"):
        box.verify_fresh_state(SEED)


def test_verify_fresh_state_refuses_a_home_directory_with_files():
    box, _ = make_box(fresh_responder(home=b"notes.txt\n"))
    with pytest.raises(HarnessError, match="home directory"):
        box.verify_fresh_state(SEED)


# --- disk and the docker binary -------------------------------------------------------------

def test_check_disk_refuses_less_than_a_gibibyte_free(monkeypatch):
    monkeypatch.setattr(lab.shutil, "disk_usage", lambda path: types.SimpleNamespace(free=100 * 2 ** 20))
    box, _ = make_box()
    with pytest.raises(HarnessError, match="disk"):
        box.check_disk()


def test_check_disk_returns_the_free_bytes(monkeypatch):
    monkeypatch.setattr(lab.shutil, "disk_usage", lambda path: types.SimpleNamespace(free=5 * 2 ** 30))
    box, _ = make_box()
    assert box.check_disk() == 5 * 2 ** 30


def test_run_docker_reports_a_missing_docker_binary(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError("docker")
    monkeypatch.setattr(lab.subprocess, "run", missing)
    with pytest.raises(HarnessError, match="docker was not found"):
        lab.run_docker(["docker", "version"])


def test_run_docker_reports_a_timeout(monkeypatch):
    def slow(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=["docker", "version"], timeout=180)
    monkeypatch.setattr(lab.subprocess, "run", slow)
    with pytest.raises(HarnessError, match="did not finish"):
        lab.run_docker(["docker", "version"])


# --- the audit's fixes (D-065) ---------------------------------------------------------------

def test_preflight_judges_the_running_containers_not_only_the_compose_file():
    # The file says hardened (GOOD_CONFIG); the live attacker is privileged. Only a check of the running
    # container can see that.
    def respond(argv):
        if argv[1] == "inspect" and "--format" not in argv and argv[2] == ATTACKER:
            info = good_inspect("attacker", "B", PROJECT)
            info["HostConfig"]["Privileged"] = True
            return 0, json.dumps([info]).encode(), b""
        return preflight_responder()(argv)

    box, _ = make_box(respond)
    with pytest.raises(HarnessError, match="live attacker: runs privileged"):
        box.preflight()


def test_preflight_fails_when_the_containers_main_process_runs_as_the_agent():
    # The file and every other live check say fine; only comparing the live container's user with the user the
    # probe measured inside the agent's own process can see that the agent could stop its own container (D-075).
    def respond(argv):
        if argv[1] == "inspect" and "--format" not in argv and argv[2] == ATTACKER:
            info = good_inspect("attacker", "B", PROJECT)
            info["Config"]["User"] = "10002:10002"
            return 0, json.dumps([info]).encode(), b""
        return preflight_responder()(argv)

    box, _ = make_box(respond)
    with pytest.raises(HarnessError, match="both run as user 10002"):
        box.preflight()


def test_preflight_fails_when_a_container_cannot_be_inspected():
    def respond(argv):
        if argv[1] == "inspect" and "--format" not in argv:
            return 1, b"", b"no such container"
        return preflight_responder()(argv)

    box, _ = make_box(respond)
    with pytest.raises(HarnessError, match="no usable record"):
        box.preflight()


def test_preflight_fails_when_the_live_network_is_not_internal():
    network = json.dumps({"Internal": False, "IPAM": {"Config": [{"Subnet": "172.18.0.0/16"}]},
                          "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"}}).encode()
    box, _ = make_box(preflight_responder(network=network))
    with pytest.raises(HarnessError, match="not internal"):
        box.preflight()


def test_the_attacker_is_running_only_when_docker_says_so():
    assert make_box(always(stdout=b"true\n"))[0].attacker_running() is True
    assert make_box(always(stdout=b"false\n"))[0].attacker_running() is False
    assert make_box(always(code=1, stderr=b"no such container"))[0].attacker_running() is False


def test_health_retries_before_calling_the_target_down(monkeypatch):
    monkeypatch.setattr(lab.time, "sleep", lambda s: None)
    answers = iter([1, 1, 0])
    box, runner = make_box(lambda argv: (next(answers), b"", b""))
    assert box.health(attempts=4) is True
    assert len(runner.calls) == 3


def test_health_gives_up_after_its_attempts(monkeypatch):
    monkeypatch.setattr(lab.time, "sleep", lambda s: None)
    box, runner = make_box(always(code=1))
    assert box.health(attempts=3) is False and len(runner.calls) == 3


def test_a_single_health_probe_is_the_default_so_waiting_for_the_port_is_not_slowed():
    box, runner = make_box(always(code=1))
    assert box.health() is False and len(runner.calls) == 1


def test_stop_attacker_kills_what_will_not_stop_and_fails_if_it_survives_that():
    state = {"running": True}

    def respond(argv):
        if argv[1] == "kill":
            state["running"] = False
        if argv[1] == "inspect" and "{{.State.Running}}" in argv:
            return 0, b"true" if state["running"] else b"false", b""
        if argv[1] == "inspect":
            return 0, b"false 137", b""
        return 0, b"", b""

    box, runner = make_box(respond)
    assert box.stop_attacker() == 137
    assert ["docker", "kill", ATTACKER] in [argv for argv, _, _ in runner.calls]

    stubborn, _ = make_box(lambda argv: (0, b"true", b"") if "{{.State.Running}}" in argv else (0, b"", b""))
    with pytest.raises(HarnessError, match="could not be stopped"):
        stubborn.stop_attacker()


def test_the_target_log_goes_to_a_file_in_the_run_directory_and_is_removed_after(tmp_path):
    box, runner = make_box(always(stdout=b'{"seq":1}\n'))
    box.work_dir = tmp_path
    box.collect_events()
    assert Path(box.runner.stdout_to).parent == tmp_path       # never the system temp directory: it can hold passwords
    assert list(tmp_path.iterdir()) == []


def test_an_oversized_target_log_is_refused_unread_and_the_scratch_file_is_removed(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, "MAX_LOG_BYTES", 10)
    box, _ = make_box(always(stdout=b'{"seq":1,"padding":"xxxxxxxxxxxxxxxxxxxx"}\n'))
    box.work_dir = tmp_path
    with pytest.raises(HarnessError, match="flooded"):
        box.collect_events()
    assert list(tmp_path.iterdir()) == []


def test_run_docker_writes_to_a_file_when_asked(tmp_path, monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen.update(kwargs)
        kwargs["stdout"].write(b"hello")
        return subprocess.CompletedProcess(argv, 0, None, b"")

    monkeypatch.setattr(lab.subprocess, "run", fake_run)
    target = tmp_path / "out"
    done = lab.run_docker(["docker", "logs", "x"], stdout_to=target)
    assert target.read_bytes() == b"hello" and "capture_output" not in seen and seen["stderr"] == subprocess.PIPE


# --- a baseline lab's preflight judges the image it runs (D-089) -----------------------------------

def baseline_responder(*, config_image="lab-baseline:dev", live_image="lab-baseline:dev"):
    """The preflight responder with the attacker's image changed in the compose config and in the running container."""
    config = copy.deepcopy(GOOD_CONFIG)
    config["services"]["attacker"]["image"] = config_image

    def respond(argv):
        if argv[1] == "inspect" and "--format" not in argv and argv[2] == ATTACKER:
            info = good_inspect("attacker", "B", PROJECT)
            info["Config"]["Image"] = live_image
            return 0, json.dumps([info]).encode(), b""
        return preflight_responder(config)(argv)
    return respond


def test_a_baseline_lab_passes_its_preflight_with_the_baseline_image():
    box, _ = make_box(baseline_responder(), baseline=True)
    assert box.preflight()["isolated"] is True


def test_a_baseline_lab_refuses_the_agents_image():
    box, _ = make_box(baseline_responder(config_image="lab-attacker:dev", live_image="lab-attacker:dev"), baseline=True)
    with pytest.raises(HarnessError, match="expected 'lab-baseline:dev'"):
        box.preflight()


def test_an_agent_lab_refuses_the_baseline_image_in_the_file_and_in_the_running_container():
    """sqlmap's image under an agent's run is the D-003 breach: both the file and the live container say so."""
    box, _ = make_box(baseline_responder())
    with pytest.raises(HarnessError) as caught:
        box.preflight()
    assert "compose: the attacker's image is 'lab-baseline:dev'" in str(caught.value)
    assert "live attacker: runs image 'lab-baseline:dev'" in str(caught.value)


def test_a_baseline_lab_refuses_a_running_container_whose_image_differs_from_the_file():
    box, _ = make_box(baseline_responder(live_image="lab-attacker:dev"), baseline=True)
    with pytest.raises(HarnessError, match="live attacker: runs image 'lab-attacker:dev'"):
        box.preflight()
