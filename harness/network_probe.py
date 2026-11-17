"""The network preflight probe. It runs INSIDE the attacker container, started by the harness (D-042).

The harness pipes this file to `docker exec -i --user agent <attacker> python3 - <gateway>`; the file
is committed so the check is reviewable, and tests import it and run the scan against a local socket.
Standard library only, because that is all the attacker image has. It prints one JSON object and
decides nothing: `preflight.evaluate_probe` reads the report and fails the run, so a probe that
cannot run at all (no output, bad JSON) also fails the run instead of passing silently.

What it asks, from the agent's own position (same user, same network):
  * can a TCP connection reach external addresses?  (it must not: the network is internal)
  * can an external hostname be resolved?           (it must not)
  * can the cloud metadata address be reached?      (it must not)
  * is there a default route at all?               (there must not be)
  * does anything answer on the bridge gateway, which is the host (D-042: Docker Desktop's rpcbind
    answered on port 111 when this was first checked)? (nothing may). The lab network has no gateway
    address now (D-066), so the harness passes none and no scan runs; the scan stays as the check for any
    network that does have one.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import sys

# Public addresses a misconfigured network could reach, on ports a firewall would usually allow.
EXTERNAL_TCP = [("1.1.1.1", 443), ("8.8.8.8", 53), ("9.9.9.9", 443)]
IMDS = ("169.254.169.254", 80)
EXTERNAL_NAME = "example.com"

# The gateway scan covers every port below 10241 and the ports local model servers and common
# services use. A full 65,535-port scan against a filtered host would take minutes (every closed
# port waits out its timeout), so the range is bounded and the list below is explicit.
KNOWN_PORTS = [11434, 1234, 3000, 3306, 5000, 5432, 5672, 6379, 8000, 8008, 8080, 8081, 8443, 8888, 9000,
               9090, 9200, 11211, 15672, 27017, 50051]
SCAN_PORTS = sorted(set(range(1, 10241)) | set(KNOWN_PORTS))
CONNECT_TIMEOUT_S = 0.5
CONCURRENCY = 200            # well under the container's file-descriptor limit, and it is one process


def tcp_connects(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def resolves(name: str) -> bool:
    try:
        socket.getaddrinfo(name, 80)
        return True
    except OSError:     # socket.gaierror is a subclass
        return False


async def _probe_port(host: str, port: int, gate: asyncio.Semaphore, timeout: float) -> int | None:
    async with gate:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        except (OSError, asyncio.TimeoutError):
            return None
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return port


async def _scan(host: str, ports: list[int], timeout: float, concurrency: int) -> list[int]:
    gate = asyncio.Semaphore(concurrency)
    found = await asyncio.gather(*(_probe_port(host, p, gate, timeout) for p in ports))
    return sorted(p for p in found if p is not None)


def scan(host: str, ports: list[int] | None = None, timeout: float = CONNECT_TIMEOUT_S,
         concurrency: int = CONCURRENCY) -> list[int]:
    """The ports on `host` that accepted a TCP connection (SCAN_PORTS unless `ports` is given; the
    default is read when called, not when defined, so a test can narrow it)."""
    return asyncio.run(_scan(host, SCAN_PORTS if ports is None else ports, timeout, concurrency))


def default_route_present(path: str = "/proc/net/route") -> bool | None:
    """Does the container have a default route? (None if the routing table cannot be read.) On the lab's
    network it must not: with no gateway there is no way out, even to the host (D-066)."""
    try:
        with open(path, encoding="ascii") as handle:
            rows = [line.split() for line in handle.read().splitlines()[1:]]
    except OSError:
        return None
    return any(len(row) > 1 and row[1] == "00000000" for row in rows)


def process_status(path: str = "/proc/self/status") -> dict:
    """What the probe's own process holds, read from the kernel: effective capabilities, no-new-privileges
    and the seccomp mode. The probe is started the way the agent's commands are, so this is the agent's
    position, not what a compose file asked for. Fields that cannot be read are None."""
    wanted = {"CapEff": "cap_eff", "NoNewPrivs": "no_new_privs", "Seccomp": "seccomp"}
    found: dict = {name: None for name in wanted.values()}
    try:
        with open(path, encoding="ascii") as handle:
            for line in handle:
                key, _, value = line.partition(":")
                if key in wanted:
                    value = value.strip()
                    found[wanted[key]] = value if key == "CapEff" else int(value)
    except (OSError, ValueError):
        pass
    return found


def build_report(gateway: str | None) -> dict:
    return {
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        **process_status(),
        "default_route": default_route_present(),
        "external_tcp": {f"{h}:{p}": tcp_connects(h, p) for h, p in EXTERNAL_TCP},
        "imds": tcp_connects(*IMDS),
        "dns": resolves(EXTERNAL_NAME),
        "gateway": gateway,
        "gateway_open_ports": scan(gateway) if gateway else None,
    }


def main(argv: list[str]) -> int:
    gateway = argv[1] if len(argv) > 1 and argv[1] else None
    print(json.dumps(build_report(gateway)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
