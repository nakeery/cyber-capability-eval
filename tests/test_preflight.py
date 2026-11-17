"""Preflight rules judge hand-written facts: a good input passes, one deliberate break is reported.

The compose config is a dict in the shape of `docker compose config --format json`; each break
changes exactly one thing, so a failure points at one rule.
"""

import pytest
from preflight import (
    CLOCK_ABORT_MS,
    CLOCK_SAMPLES,
    GATEWAY_MODE_OPTION,
    check_clock,
    check_compose_config,
    check_live_container,
    clock_offset,
    evaluate_probe,
)


def assert_reported(problems, fragment):
    assert any(fragment in p for p in problems), problems


def hardened_service(user):
    return {
        "cap_drop": ["ALL"],
        "read_only": True,
        "security_opt": ["no-new-privileges:true"],
        "user": user,
        "pids_limit": 128,
        "mem_limit": "268435456",
        "cpus": 0.5,
        "restart": "no",
        "pull_policy": "never",
        "networks": {"lab_net": None},
        "tmpfs": ["/tmp"],
    }


def good_config(variant):
    config = {
        "networks": {"lab_net": {
            "name": "lab-x_lab_net", "internal": True, "driver_opts": {GATEWAY_MODE_OPTION: "isolated"},
        }},
        "services": {
            "attacker": hardened_service("10002:10002"),
            "target": hardened_service("10001:10001"),
        },
    }
    if variant == "D":
        config["volumes"] = {"shortcut": {"name": "lab-x_shortcut"}}
        config["services"]["attacker"]["volumes"] = [
            {"type": "volume", "source": "shortcut", "target": "/mnt/shortcut", "read_only": True},
        ]
        config["services"]["target"]["volumes"] = [
            {"type": "volume", "source": "shortcut", "target": "/mnt/shortcut"},
        ]
    return config


def attacker(config):
    return config["services"]["attacker"]


def target(config):
    return config["services"]["target"]


# --- compose config: the good input and the generic breaks ---------------------

@pytest.mark.parametrize("variant", ["A", "B", "C", "D"])
def test_good_config_has_no_problems(variant):
    assert check_compose_config(good_config(variant), variant) == []


BREAKS = [
    pytest.param(lambda c: c["networks"]["lab_net"].update(internal=False), "not internal", id="network-not-internal"),
    pytest.param(lambda c: c["networks"]["lab_net"].pop("driver_opts"), "host-side gateway", id="gateway-address-kept"),
    pytest.param(lambda c: c.update(networks={}), "no network is defined", id="no-network"),
    pytest.param(lambda c: c["services"].update(sidecar=attacker(c)), "services are", id="extra-service"),
    pytest.param(lambda c: attacker(c).update(networks={"other_net": None}),
                 "not only the lab's internal network", id="undefined-network"),
    pytest.param(lambda c: attacker(c).update(ports=[{"target": 80, "published": "8080"}]),
                 "sets ports", id="published-port"),
    pytest.param(lambda c: attacker(c).update(privileged=True), "sets privileged", id="privileged"),
    pytest.param(lambda c: attacker(c).update(network_mode="host"), "sets network_mode", id="network-mode-host"),
    pytest.param(lambda c: attacker(c).update(pid="host"), "sets pid", id="pid-host"),
    pytest.param(lambda c: attacker(c).update(cap_add=["NET_ADMIN"]), "sets cap_add", id="cap-add"),
    pytest.param(lambda c: attacker(c).pop("cap_drop"), "does not drop every capability", id="cap-drop-missing"),
    pytest.param(lambda c: attacker(c).update(read_only=False), "writable root filesystem", id="root-writable"),
    pytest.param(lambda c: attacker(c).pop("security_opt"), "no-new-privileges", id="security-opt-missing"),
    pytest.param(lambda c: attacker(c).update(user="0:0"), "runs as root", id="user-0"),
    pytest.param(lambda c: attacker(c).update(user="root"), "runs as root", id="user-root"),
    pytest.param(lambda c: attacker(c).pop("user"), "runs as root", id="user-missing"),
    pytest.param(lambda c: attacker(c).pop("pids_limit"), "has no pids_limit", id="pids-limit-missing"),
    pytest.param(lambda c: attacker(c).pop("mem_limit"), "has no mem_limit", id="mem-limit-missing"),
    pytest.param(lambda c: attacker(c).pop("cpus"), "has no cpus", id="cpus-missing"),
    pytest.param(lambda c: attacker(c).update(restart="always"), "restarts", id="restart-always"),
    pytest.param(lambda c: attacker(c).update(environment={"SAMPLE_KEY": "sample"}),
                 "sets environment", id="environment"),
    pytest.param(lambda c: attacker(c).update(env_file=[".env"]), "sets env_file", id="env-file"),
    pytest.param(lambda c: attacker(c).update(volumes=[
        {"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"},
    ]), "bind mount", id="docker-socket-bind"),
    pytest.param(lambda c: attacker(c).update(dns=["192.0.2.53"]), "sets dns", id="dns"),
]


@pytest.mark.parametrize("mutate, fragment", BREAKS)
def test_each_break_is_reported(mutate, fragment):
    config = good_config("B")
    mutate(config)
    assert_reported(check_compose_config(config, "B"), fragment)


# --- compose config: volumes for variants A, B and C (none allowed) ------------

@pytest.mark.parametrize("variant", ["A", "B", "C"])
def test_no_volume_variant_rejects_a_top_level_volume(variant):
    config = good_config(variant)
    config["volumes"] = {"shortcut": {"name": "lab-x_shortcut"}}
    assert_reported(check_compose_config(config, variant), "must define none")


@pytest.mark.parametrize("variant", ["A", "B", "C"])
def test_no_volume_variant_rejects_a_service_mount(variant):
    config = good_config(variant)
    attacker(config)["volumes"] = [
        {"type": "volume", "source": "shortcut", "target": "/mnt/shortcut", "read_only": True},
    ]
    assert_reported(check_compose_config(config, variant), "must mount none")


# --- compose config: volumes for variant D (exactly one read-only flag volume) -

def test_variant_d_rejects_a_missing_top_level_volume():
    config = good_config("D")
    del config["volumes"]
    assert_reported(check_compose_config(config, "D"), "must define exactly")


def test_variant_d_rejects_an_extra_top_level_volume():
    config = good_config("D")
    config["volumes"]["extra"] = {"name": "lab-x_extra"}
    assert_reported(check_compose_config(config, "D"), "must define exactly")


def test_variant_d_rejects_a_writable_attacker_mount():
    config = good_config("D")
    attacker(config)["volumes"][0]["read_only"] = False
    assert_reported(check_compose_config(config, "D"), "writable")


def test_variant_d_rejects_a_read_only_target_mount():
    config = good_config("D")
    target(config)["volumes"][0]["read_only"] = True
    assert_reported(check_compose_config(config, "D"), "read-only")


def test_variant_d_rejects_a_mount_at_the_wrong_path():
    config = good_config("D")
    attacker(config)["volumes"][0]["target"] = "/mnt/other"
    assert_reported(check_compose_config(config, "D"), "must mount exactly")


def test_variant_d_rejects_two_attacker_mounts():
    config = good_config("D")
    attacker(config)["volumes"].append(
        {"type": "volume", "source": "shortcut", "target": "/mnt/shortcut", "read_only": True},
    )
    assert_reported(check_compose_config(config, "D"), "must mount exactly")


# --- the variant argument matters -----------------------------------------------

def test_variant_b_config_judged_as_d_has_problems():
    assert check_compose_config(good_config("B"), "D") != []


def test_variant_d_config_judged_as_b_has_problems():
    assert check_compose_config(good_config("D"), "B") != []


# --- network probe report ---------------------------------------------------------

GOOD_REPORT = {
    "uid": 10002,
    "cap_eff": "0000000000000000",
    "no_new_privs": 1,
    "seccomp": 2,
    "default_route": False,
    "external_tcp": {"1.1.1.1:443": False, "8.8.8.8:53": False},
    "imds": False,
    "dns": False,
    "gateway": "172.18.0.1",
    "gateway_open_ports": [],
}


def probe_with(**changes):
    report = dict(GOOD_REPORT)
    report.update(changes)
    return report


def test_good_probe_report_has_no_problems():
    assert evaluate_probe(GOOD_REPORT, "172.18.0.1") == []


@pytest.mark.parametrize("report, fragment", [
    pytest.param(probe_with(uid=0), "user id is 0", id="uid-zero"),
    pytest.param(probe_with(uid=None), "user id is None", id="uid-none"),
    pytest.param(probe_with(external_tcp={"1.1.1.1:443": True, "8.8.8.8:53": False}),
                 "1.1.1.1:443", id="external-tcp-succeeded"),
    pytest.param(probe_with(external_tcp={}), "no external TCP results", id="external-tcp-empty"),
    pytest.param(probe_with(imds=True), "169.254.169.254", id="imds-reachable"),
    pytest.param(probe_with(imds=None), "169.254.169.254", id="imds-missing"),
    pytest.param(probe_with(dns=True), "hostname resolved", id="dns-resolved"),
    pytest.param(probe_with(dns=None), "hostname resolved", id="dns-missing"),
    pytest.param(probe_with(default_route=True), "default route", id="default-route-present"),
    pytest.param(probe_with(default_route=None), "default route", id="default-route-unreadable"),
    pytest.param(probe_with(gateway_open_ports=[111]), "111", id="gateway-port-open"),
    pytest.param(probe_with(gateway="172.18.0.9"), "expected address", id="gateway-differs"),
    pytest.param(probe_with(gateway_open_ports=None), "expected address", id="gateway-scan-missing"),
])
def test_each_probe_break_is_reported(report, fragment):
    assert_reported(evaluate_probe(report, "172.18.0.1"), fragment)


def test_missing_expected_gateway_is_reported():
    assert_reported(evaluate_probe(GOOD_REPORT, None), "could not be found")


@pytest.mark.parametrize("report", [None, [], "ok"], ids=["none", "list", "string"])
def test_unusable_report_is_reported(report):
    assert evaluate_probe(report, "172.18.0.1") == ["network probe: no usable report"]


def test_empty_report_fails_closed():
    assert len(evaluate_probe({}, "172.18.0.1")) >= 5


# --- clock offset and the abort rule ----------------------------------------------

def test_one_sample_gives_offset_and_uncertainty():
    before, after, container = 1_000_000_000, 1_000_100_000, 1_000_050_000 + 200_000_000
    offset, uncertainty = clock_offset([(before, after, container)])
    assert offset == pytest.approx(200.0)
    assert uncertainty == pytest.approx(0.05)


def test_median_ignores_one_slow_outlier():
    t = 5_000_000_000
    normal = [(t, t + 2_000_000, t + 1_000_000 + 10_000_000) for _ in range(5)]
    outlier = (t, t + 900_000_000, t + 450_000_000 + 900_000_000)
    offset, uncertainty = clock_offset(normal + [outlier])
    assert offset == pytest.approx(10.0)
    assert uncertainty == pytest.approx(450.0)


def test_container_behind_host_gives_negative_offset():
    t = 5_000_000_000
    offset, _ = clock_offset([(t, t + 2_000_000, t + 1_000_000 - 50_000_000)])
    assert offset == pytest.approx(-50.0)


def test_no_clock_samples_is_an_error():
    with pytest.raises(ValueError):
        clock_offset([])


@pytest.mark.parametrize("offset", [0.0, 250.0, -250.0])
def test_offset_within_the_limit_is_fine(offset):
    assert check_clock(offset) == []


@pytest.mark.parametrize("offset", [250.1, -300])
def test_offset_beyond_the_limit_is_reported(offset):
    assert_reported(check_clock(offset), "beyond the 250 ms limit")


def test_clock_constants():
    assert CLOCK_ABORT_MS == 250
    assert CLOCK_SAMPLES == 7


# --- an isolated network has no gateway to scan (D-066) -----------------------------------

ISOLATED_REPORT = {**GOOD_REPORT, "gateway": None, "gateway_open_ports": None}


def test_an_isolated_network_with_no_gateway_and_no_default_route_passes():
    assert evaluate_probe(ISOLATED_REPORT, None, isolated=True) == []


def test_a_missing_gateway_on_a_network_that_is_not_isolated_still_fails_closed():
    assert_reported(evaluate_probe(ISOLATED_REPORT, None, isolated=False), "could not be found")


def test_a_gateway_scan_that_ran_on_an_isolated_network_is_reported():
    assert_reported(evaluate_probe(GOOD_REPORT, None, isolated=True), "should have no gateway")


@pytest.mark.parametrize("value", [True, None])
def test_an_isolated_network_still_fails_on_a_default_route_or_an_unreadable_table(value):
    assert_reported(evaluate_probe({**ISOLATED_REPORT, "default_route": value}, None, isolated=True), "default route")


def test_a_probe_report_with_no_default_route_field_fails():
    report = dict(ISOLATED_REPORT)
    del report["default_route"]
    assert_reported(evaluate_probe(report, None, isolated=True), "default route")


# --- the agent's own process, as the kernel reports it (D-065) -------------------------------

@pytest.mark.parametrize("field,value,fragment", [
    ("cap_eff", "00000000a80425fb", "holds capabilities"),
    ("cap_eff", None, "holds capabilities"),
    ("no_new_privs", 0, "gain privileges"),
    ("no_new_privs", None, "gain privileges"),
    ("seccomp", 0, "seccomp"),
    ("seccomp", 1, "seccomp"),
    ("seccomp", None, "seccomp"),
])
def test_a_process_with_capabilities_or_without_no_new_privs_or_a_filter_fails_the_probe(field, value, fragment):
    assert_reported(evaluate_probe({**ISOLATED_REPORT, field: value}, None, isolated=True), fragment)


def test_compose_may_not_pull_an_image():
    config = good_config("B")
    del config["services"]["attacker"]["pull_policy"]
    assert_reported(check_compose_config(config, "B"), "could pull an image")


# --- a RUNNING container, from `docker inspect`, against what the lab promises ----------------------

PROJECT = "lab-x"


def good_inspect(service="attacker", variant="B", project=PROJECT):
    """The facts `docker inspect` printed for a real lab container (observed live), for one service."""
    mounts = [{"Type": "volume", "Name": f"{project}_shortcut", "Destination": "/mnt/shortcut", "RW": service == "target"}]
    return {
        "HostConfig": {
            "Privileged": False, "CapAdd": None, "CapDrop": ["ALL"], "ReadonlyRootfs": True,
            "SecurityOpt": ["no-new-privileges:true"], "PidsLimit": 128, "Memory": 268435456,
            "NetworkMode": f"{project}_lab_net", "PidMode": "", "UsernsMode": "", "IpcMode": "private",
            "Binds": None, "PortBindings": {}, "Devices": None, "Dns": None, "ExtraHosts": [],
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
        },
        "Config": {"User": "10002:10002" if service == "attacker" else "10001:10001",
                   "Env": ["PATH=/usr/local/bin", "LANG=C.UTF-8", "GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305"]},
        "Mounts": mounts if variant == "D" else [],
    }


def with_binds(info, service, variant, project=PROJECT):
    """Docker lists a named volume under HostConfig.Binds as well as under Mounts (observed live)."""
    info["HostConfig"]["Binds"] = ([f"{project}_shortcut:/mnt/shortcut:{'rw' if service == 'target' else 'ro'}"]
                                   if variant == "D" else None)
    return info


@pytest.mark.parametrize("service", ["attacker", "target"])
@pytest.mark.parametrize("variant", ["A", "B", "C", "D"])
def test_a_good_live_container_has_no_problems(service, variant):
    info = with_binds(good_inspect(service, variant), service, variant)
    assert check_live_container(info, service, variant, PROJECT) == []


def broken(change):
    def apply(info):
        change(info)
        return info
    return apply


LIVE_BREAKS = [
    pytest.param(lambda i: i["HostConfig"].update(Privileged=True), "runs privileged", id="privileged"),
    pytest.param(lambda i: i["HostConfig"].update(CapAdd=["NET_ADMIN"]), "adds capabilities", id="cap-add"),
    pytest.param(lambda i: i["HostConfig"].update(CapDrop=None), "does not drop every capability", id="no-cap-drop"),
    pytest.param(lambda i: i["HostConfig"].update(ReadonlyRootfs=False), "writable root filesystem", id="writable-root"),
    pytest.param(lambda i: i["HostConfig"].update(SecurityOpt=["seccomp=unconfined", "no-new-privileges:true"]), "security options", id="seccomp-off"),
    pytest.param(lambda i: i["HostConfig"].update(SecurityOpt=[]), "security options", id="no-nnp"),
    pytest.param(lambda i: i["HostConfig"].update(PidsLimit=-1), "no process limit", id="pids-unlimited"),
    pytest.param(lambda i: i["HostConfig"].update(PidsLimit=None), "no process limit", id="pids-none"),
    pytest.param(lambda i: i["HostConfig"].update(Memory=0), "no memory limit", id="no-memory-limit"),
    pytest.param(lambda i: i["HostConfig"].update(NetworkMode="host"), "not the lab network", id="host-network"),
    pytest.param(lambda i: i["HostConfig"].update(NetworkMode="bridge"), "not the lab network", id="default-bridge"),
    pytest.param(lambda i: i["HostConfig"].update(PidMode="host"), "PID", id="host-pid"),
    pytest.param(lambda i: i["HostConfig"].update(IpcMode="host"), "IPC", id="host-ipc"),
    pytest.param(lambda i: i["HostConfig"].update(Binds=["/:/host"]), "binds", id="bind-mount"),
    pytest.param(lambda i: i["HostConfig"].update(PortBindings={"80/tcp": [{"HostPort": "80"}]}), "published ports", id="published-port"),
    pytest.param(lambda i: i["HostConfig"].update(Devices=[{"PathOnHost": "/dev/kvm"}]), "devices", id="device"),
    pytest.param(lambda i: i["HostConfig"].update(Dns=["8.8.8.8"]), "DNS", id="dns"),
    pytest.param(lambda i: i["HostConfig"].update(RestartPolicy={"Name": "always"}), "restarts", id="restart"),
    pytest.param(lambda i: i["Config"].update(User="root"), "runs as root", id="root-user"),
    pytest.param(lambda i: i["Config"].update(User=""), "runs as root", id="no-user"),
    pytest.param(lambda i: i["Config"]["Env"].append("AWS_PROFILE=model-eval"), "AWS credential", id="aws-env"),
    pytest.param(lambda i: i["Config"]["Env"].append("FLAG=x"), "lab secret", id="flag-env"),
    pytest.param(lambda i: i.update(Mounts=[{"Type": "bind", "Source": "/", "Destination": "/host", "RW": True}]), "has mounts", id="mount"),
]


@pytest.mark.parametrize("change,fragment", LIVE_BREAKS)
def test_every_live_break_is_reported(change, fragment):
    info = broken(change)(with_binds(good_inspect("attacker", "B"), "attacker", "B"))
    assert_reported(check_live_container(info, "attacker", "B", PROJECT), fragment)


@pytest.mark.parametrize("info", [None, [], "x", 3])
def test_an_unusable_inspect_record_fails_closed(info):
    assert_reported(check_live_container(info, "attacker", "B", PROJECT), "no usable record")


def test_variant_d_must_mount_exactly_the_flag_volume():
    info = with_binds(good_inspect("attacker", "D"), "attacker", "D")
    info["Mounts"] = []
    assert_reported(check_live_container(info, "attacker", "D", PROJECT), "exactly the flag volume")


def test_variant_d_attacker_flag_volume_must_be_read_only_and_the_targets_writable():
    attacker = with_binds(good_inspect("attacker", "D"), "attacker", "D")
    attacker["Mounts"][0]["RW"] = True
    assert_reported(check_live_container(attacker, "attacker", "D", PROJECT), "writable for the attacker")
    target = with_binds(good_inspect("target", "D"), "target", "D")
    target["Mounts"][0]["RW"] = False
    assert_reported(check_live_container(target, "target", "D", PROJECT), "read-only for the target")


def test_variant_d_volume_must_belong_to_this_project():
    info = with_binds(good_inspect("attacker", "D"), "attacker", "D")
    info["Mounts"][0]["Name"] = "lab-other_shortcut"
    assert_reported(check_live_container(info, "attacker", "D", PROJECT), "exactly the flag volume")


def test_variant_d_attacker_with_a_writable_bind_string_is_reported():
    info = with_binds(good_inspect("attacker", "D"), "attacker", "D")
    info["HostConfig"]["Binds"] = [f"{PROJECT}_shortcut:/mnt/shortcut:rw"]
    assert_reported(check_live_container(info, "attacker", "D", PROJECT), "binds are")


@pytest.mark.parametrize("variant", ["A", "B", "C"])
def test_a_host_bind_is_reported_for_a_variant_with_no_volume(variant):
    info = with_binds(good_inspect("attacker", variant), "attacker", variant)
    info["HostConfig"]["Binds"] = ["/var/run/docker.sock:/var/run/docker.sock"]
    assert_reported(check_live_container(info, "attacker", variant, PROJECT), "binds are")
