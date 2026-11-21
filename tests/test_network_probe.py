"""The network probe runs against 127.0.0.1 here (no container), with its external targets patched out.

Patching `scan` as well is deliberate: `scan`'s default `ports` is bound when the function is
defined, so patching `SCAN_PORTS` does not reach `build_report` (a full scan of the loopback
interface would take about 30 seconds).
"""

import ast
import json
import socket
from pathlib import Path

import pytest
import network_probe

PROBE_SOURCE = Path(network_probe.__file__)
STDLIB_ALLOW_LIST = {"asyncio", "importlib", "json", "os", "shutil", "socket", "sys", "__future__"}


def listening_socket():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    return listener


@pytest.fixture
def open_port():
    listener = listening_socket()
    yield listener.getsockname()[1]
    listener.close()


@pytest.fixture
def closed_port():
    probe = listening_socket()
    port = probe.getsockname()[1]
    probe.close()
    return port


@pytest.fixture
def offline(monkeypatch, closed_port):
    monkeypatch.setattr(network_probe, "EXTERNAL_TCP", [("127.0.0.1", closed_port)])
    monkeypatch.setattr(network_probe, "IMDS", ("127.0.0.1", closed_port))
    monkeypatch.setattr(network_probe, "EXTERNAL_NAME", "this-name-does-not-exist.invalid")


def pin_scan(monkeypatch, ports):
    real_scan = network_probe.scan
    monkeypatch.setattr(network_probe, "scan", lambda host, **kwargs: real_scan(host, ports, **kwargs))


REPORT_KEYS = {"uid", "cap_eff", "no_new_privs", "seccomp", "default_route", "external_tcp", "imds", "dns", "sqlmap",
               "gateway", "gateway_open_ports"}


# --- scanning and connecting -------------------------------------------------------

def test_scan_finds_only_the_open_port(open_port, closed_port):
    assert network_probe.scan("127.0.0.1", [open_port, closed_port], timeout=1.0) == [open_port]


def test_scan_of_no_ports_finds_nothing():
    assert network_probe.scan("127.0.0.1", []) == []


def test_tcp_connects_to_an_open_port(open_port):
    assert network_probe.tcp_connects("127.0.0.1", open_port) is True


def test_tcp_connects_to_a_closed_port(closed_port):
    assert network_probe.tcp_connects("127.0.0.1", closed_port) is False


def test_localhost_resolves():
    assert network_probe.resolves("localhost") is True


def test_invalid_name_does_not_resolve():
    assert network_probe.resolves("this-name-does-not-exist.invalid") is False


# --- the port list ---------------------------------------------------------------------

def test_scan_ports_cover_the_low_range_and_local_model_servers():
    assert 111 in network_probe.SCAN_PORTS
    assert 11434 in network_probe.SCAN_PORTS


def test_scan_ports_exclude_port_zero():
    assert 0 not in network_probe.SCAN_PORTS


def test_scan_ports_are_sorted_without_duplicates():
    assert network_probe.SCAN_PORTS == sorted(set(network_probe.SCAN_PORTS))


# --- the report -------------------------------------------------------------------------

def test_report_has_exactly_the_expected_keys(offline):
    assert set(network_probe.build_report(None)) == REPORT_KEYS


def test_report_without_a_gateway_skips_the_scan(offline, closed_port):
    report = network_probe.build_report(None)
    assert report["external_tcp"] == {f"127.0.0.1:{closed_port}": False}
    assert report["imds"] is False
    assert report["dns"] is False
    assert report["gateway"] is None
    assert report["gateway_open_ports"] is None


def test_report_scans_the_gateway(offline, monkeypatch, open_port, closed_port):
    pin_scan(monkeypatch, [open_port, closed_port])
    assert network_probe.build_report("127.0.0.1")["gateway_open_ports"] == [open_port]


# --- the command line -------------------------------------------------------------------

def test_main_prints_one_json_line_and_returns_zero(offline, monkeypatch, capsys, closed_port):
    pin_scan(monkeypatch, [closed_port])
    code = network_probe.main(["-", "127.0.0.1"])
    lines = capsys.readouterr().out.splitlines()
    assert code == 0
    assert len(lines) == 1
    assert set(json.loads(lines[0])) == REPORT_KEYS


@pytest.mark.parametrize("argv", [["-"], ["-", ""]], ids=["no-gateway-argument", "empty-gateway-argument"])
def test_main_without_a_gateway_reports_none(offline, capsys, argv):
    network_probe.main(argv)
    report = json.loads(capsys.readouterr().out)
    assert report["gateway"] is None
    assert report["gateway_open_ports"] is None


# --- stdlib only ------------------------------------------------------------------------

def test_probe_imports_only_the_standard_library():
    tree = ast.parse(PROBE_SOURCE.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported <= STDLIB_ALLOW_LIST, imported - STDLIB_ALLOW_LIST


# --- the routing table (D-066) ----------------------------------------------------------

ROUTE_HEADER = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
SUBNET_ROW = "eth0\t000012AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
DEFAULT_ROW = "eth0\t00000000\t010012AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"


def test_a_subnet_route_alone_is_not_a_default_route(tmp_path):
    table = tmp_path / "route"
    table.write_text(ROUTE_HEADER + SUBNET_ROW, encoding="ascii")
    assert network_probe.default_route_present(str(table)) is False


def test_a_default_route_is_found(tmp_path):
    table = tmp_path / "route"
    table.write_text(ROUTE_HEADER + SUBNET_ROW + DEFAULT_ROW, encoding="ascii")
    assert network_probe.default_route_present(str(table)) is True


def test_an_empty_table_has_no_default_route(tmp_path):
    table = tmp_path / "route"
    table.write_text(ROUTE_HEADER, encoding="ascii")
    assert network_probe.default_route_present(str(table)) is False


def test_an_unreadable_routing_table_is_unknown_not_clean(tmp_path):
    assert network_probe.default_route_present(str(tmp_path / "missing")) is None


def test_scan_reads_its_default_port_list_when_called_not_when_defined(monkeypatch, open_port, closed_port):
    monkeypatch.setattr(network_probe, "SCAN_PORTS", [open_port, closed_port])
    assert network_probe.scan("127.0.0.1", timeout=1.0) == [open_port]


# --- what the agent's own process holds (D-065) ---------------------------------------

STATUS = "Name:\tpython3\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n"


def test_process_status_reads_capabilities_no_new_privs_and_seccomp(tmp_path):
    status = tmp_path / "status"
    status.write_text(STATUS, encoding="ascii")
    assert network_probe.process_status(str(status)) == {"cap_eff": "0000000000000000", "no_new_privs": 1, "seccomp": 2}


def test_a_process_with_capabilities_and_no_filter_is_reported_as_it_is(tmp_path):
    status = tmp_path / "status"
    status.write_text(STATUS.replace("CapEff:\t0000000000000000", "CapEff:\t00000000a80425fb")
                      .replace("NoNewPrivs:\t1", "NoNewPrivs:\t0").replace("Seccomp:\t2", "Seccomp:\t0"), encoding="ascii")
    assert network_probe.process_status(str(status)) == {"cap_eff": "00000000a80425fb", "no_new_privs": 0, "seccomp": 0}


def test_an_unreadable_status_gives_none_for_every_field_not_a_clean_default(tmp_path):
    assert network_probe.process_status(str(tmp_path / "missing")) == {"cap_eff": None, "no_new_privs": None, "seccomp": None}


def test_a_status_without_the_fields_gives_none(tmp_path):
    status = tmp_path / "status"
    status.write_text("Name:\tpython3\n", encoding="ascii")
    assert network_probe.process_status(str(status)) == {"cap_eff": None, "no_new_privs": None, "seccomp": None}


# --- is sqlmap in this container? (D-003, D-091) --------------------------------------------

def test_sqlmap_is_present_when_a_program_is_on_the_path():
    assert network_probe.sqlmap_present(which=lambda name: "/usr/local/bin/sqlmap", find_spec=lambda name: None) is True


def test_sqlmap_is_present_when_a_package_is_importable():
    assert network_probe.sqlmap_present(which=lambda name: None, find_spec=lambda name: object()) is True


def test_sqlmap_is_absent_when_neither_finder_sees_it():
    assert network_probe.sqlmap_present(which=lambda name: None, find_spec=lambda name: None) is False


def test_sqlmap_is_looked_up_by_its_own_name():
    asked = []
    network_probe.sqlmap_present(which=lambda name: asked.append(name), find_spec=lambda name: asked.append(name))
    assert asked == ["sqlmap", "sqlmap"]


@pytest.mark.parametrize("error", [ImportError, ValueError])
def test_a_finder_that_raises_counts_as_not_found(error):
    def boom(name):
        raise error(name)
    assert network_probe.sqlmap_present(which=lambda name: None, find_spec=boom) is False


def test_the_report_carries_the_finding(offline):
    assert isinstance(network_probe.build_report(None)["sqlmap"], bool)
