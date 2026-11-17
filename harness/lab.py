"""The lab's Docker lifecycle for one run (PLAN.md phase 4, D-034, D-037, D-041, D-042).

Every Docker call goes through one `Runner` and is an argv list with `shell=False`; the container
and project names come only from the harness (a validated run id). Nothing the agent writes reaches
a host shell, and the seed (which holds the flag and the admin password) travels on stdin only, never
in an argument or an environment variable.

Order of a run's life, driven by run.py:
    sweep -> assert_clean -> up -> preflight -> seed -> wait_ready -> verify_fresh_state ->
    measure_clock -> [the agent loop] -> stop_attacker -> measure_clock -> stop_target ->
    collect_events -> down

Why that end order: the attacker is stopped first, so nothing it left running can touch the target
after the run's `ended_at` (D-037); the clock is measured again while the target still runs; the
target is stopped before its log is read, because `docker logs` of a running container races the log
driver's copier, while a stopped container's log is complete.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "target"))
sys.path.insert(0, str(ROOT / "harness"))

from db import ADMIN_USERNAME, DECOY_USERNAMES, ITEMS  # noqa: E402  (stdlib only; never imports Flask)
from execution import _popen_kwargs  # noqa: E402
from preflight import (CLOCK_SAMPLES, GATEWAY_MODE_OPTION, check_clock, check_compose_config,  # noqa: E402
                       check_live_container, clock_offset, evaluate_probe)
from target_logs import collect_events  # noqa: E402

RUN_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")     # a uuid4's hex form, the same as schemas/label.schema.json
PROJECT_PREFIX = "lab-"
PROJECT_LABEL = "com.docker.compose.project"
BASE_FILE, D_FILE = ROOT / "docker-compose.yml", ROOT / "docker-compose.d.yml"
TARGET_UID = "10001"
READY_TIMEOUT_S = 30
MIN_FREE_BYTES = 1024 ** 3            # D-042: the log has no rotation, so a nearly full disk ends a run badly
MAX_LOG_BYTES = 50 * 1024 * 1024
DOCKER_TIMEOUT_S = 180


class HarnessError(Exception):
    """A preflight, lifecycle or collection failure: the run ends as `harness_error` (D-064)."""


class Runner(Protocol):
    def __call__(self, argv: list[str], *, input: bytes | None = None, timeout: float = DOCKER_TIMEOUT_S,
                 stdout_to: Path | None = None) -> subprocess.CompletedProcess: ...


def run_docker(argv: list[str], *, input: bytes | None = None, timeout: float = DOCKER_TIMEOUT_S,
               stdout_to: Path | None = None) -> subprocess.CompletedProcess:
    """Run one docker command. With `stdout_to`, stdout goes straight to that file (and the result's stdout is
    empty), so an enormous output is bounded by the disk, not held in memory."""
    try:
        if stdout_to is not None:
            with open(stdout_to, "wb") as sink:
                return subprocess.run(argv, input=input, stdout=sink, stderr=subprocess.PIPE, timeout=timeout,
                                      cwd=ROOT, shell=False, **_popen_kwargs())
        return subprocess.run(argv, input=input, capture_output=True, timeout=timeout, cwd=ROOT,
                              shell=False, **_popen_kwargs())
    except FileNotFoundError:
        raise HarnessError("docker was not found: is Docker Desktop installed and running?") from None
    except subprocess.TimeoutExpired:
        raise HarnessError(f"`{' '.join(argv[:3])} ...` did not finish within {timeout:.0f} s") from None


def project_name(run_id: str) -> str:
    if not RUN_ID_PATTERN.match(run_id):
        raise HarnessError("the run id is not a uuid4 hex string")
    return PROJECT_PREFIX + run_id


def is_lab_project(name: str) -> bool:
    return name.startswith(PROJECT_PREFIX) or name == "lab"


def compose_files(variant: str) -> list[Path]:
    """An allow-list: the base file, plus the D override for variant D and nothing else."""
    return [BASE_FILE, D_FILE] if variant == "D" else [BASE_FILE]


def parse_labels(text: str) -> dict[str, str]:
    """Docker prints labels as one `k=v,k=v` string. Only the project label matters here."""
    pairs = (item.split("=", 1) for item in (text or "").split(",") if "=" in item)
    return {key: value for key, value in pairs}


def _text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").strip()


@dataclass
class Lab:
    variant: str
    run_id: str
    runner: Runner = run_docker
    work_dir: Path | None = None    # where the target's log is written while it is read; run.py sets the run's directory

    def __post_init__(self) -> None:
        self.project = project_name(self.run_id)
        self.attacker = f"{self.project}-attacker-1"
        self.target = f"{self.project}-target-1"

    # --- plumbing -------------------------------------------------------------------------

    def _docker(self, *args: str, input: bytes | None = None, check: bool = True,
                timeout: float = DOCKER_TIMEOUT_S, stdout_to: Path | None = None) -> subprocess.CompletedProcess:
        extra = {"stdout_to": stdout_to} if stdout_to is not None else {}
        done = self.runner(["docker", *args], input=input, timeout=timeout, **extra)
        if check and done.returncode != 0:
            raise HarnessError(f"`docker {' '.join(args[:2])}` failed (exit {done.returncode}): "
                               f"{_text(done.stderr)[:300]}")
        return done

    def _compose(self, *args: str, check: bool = True, timeout: float = DOCKER_TIMEOUT_S):
        files = [part for path in compose_files(self.variant) for part in ("-f", str(path))]
        return self._docker("compose", "-p", self.project, *files, *args, check=check, timeout=timeout)

    def _exec(self, container: str, *args: str, user: str | None = None, input: bytes | None = None,
              check: bool = True, timeout: float = 60):
        flags = ["-i"] if input is not None else []
        flags += ["--user", user] if user else []
        return self._docker("exec", *flags, container, *args, input=input, check=check, timeout=timeout)

    # --- before: leftovers, disk, up --------------------------------------------------------

    def leftovers(self, project: str | None = None) -> dict[str, list[str]]:
        """Containers, networks and volumes that belong to a lab project, whoever started them: every lab
        project by default, or only `project`."""
        found: dict[str, list[str]] = {"containers": [], "networks": [], "volumes": []}
        listings = (("containers", ["ps", "-a"], "ID"), ("networks", ["network", "ls"], "ID"),
                    ("volumes", ["volume", "ls"], "Name"))
        for kind, command, key in listings:
            out = self._docker(*command, "--filter", f"label={PROJECT_LABEL}", "--format", "{{json .}}")
            for line in _text(out.stdout).splitlines():
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:    # e.g. a warning Docker printed on stdout: never a raw traceback
                    raise HarnessError(f"`docker {' '.join(command)}` printed a line that is not JSON: {line[:100]!r}") from None
                owner = parse_labels(row.get("Labels", "")).get(PROJECT_LABEL, "")
                if (owner == project) if project else is_lab_project(owner):
                    found[kind].append(row[key])
        return found

    def _remove(self, found: dict[str, list[str]]) -> None:
        if found["containers"]:
            self._docker("rm", "-f", "-v", *found["containers"], check=False)
        if found["networks"]:
            self._docker("network", "rm", *found["networks"], check=False)
        if found["volumes"]:
            self._docker("volume", "rm", "-f", *found["volumes"], check=False)

    def sweep(self) -> dict[str, int]:
        """Remove anything a crashed earlier run left behind (D-042 item 2). Returns what it removed."""
        found = self.leftovers()
        self._remove(found)
        return {kind: len(ids) for kind, ids in found.items()}

    def assert_clean(self) -> None:
        """The clean-state check (PLAN.md phase 4 done-when): no lab containers, volumes or networks."""
        left = {kind: ids for kind, ids in self.leftovers().items() if ids}
        if left:
            raise HarnessError(f"lab resources are still present before `up`: { {k: len(v) for k, v in left.items()} }")

    def check_disk(self) -> int:
        free = shutil.disk_usage(ROOT).free
        if free < MIN_FREE_BYTES:
            raise HarnessError(f"only {free // 2 ** 20} MiB of disk is free; the target's log has no rotation (D-042)")
        return free

    def build_images(self) -> None:
        self._compose("build", timeout=900)

    def up(self) -> None:
        # --no-build: the images are the ones `build` made and the preflight recorded, never a surprise rebuild.
        done = self._compose("up", "-d", "--no-build", check=False, timeout=300)
        if done.returncode != 0:
            raise HarnessError(f"compose up failed (are the images built? run `run.py build`): {_text(done.stderr)[:300]}")

    def down(self) -> list[str]:
        """Remove this run's stack and its volumes. Returns what is STILL there afterwards (empty if clean):
        a leftover is forced out once, and reported if it survives that too."""
        self._compose("down", "-v", "-t", "3", check=False, timeout=120)
        mine = self.leftovers(self.project)
        if any(mine.values()):
            self._remove(mine)
            mine = self.leftovers(self.project)
        return [f"{kind}:{len(ids)}" for kind, ids in mine.items() if ids]

    # --- preflight ----------------------------------------------------------------------

    def network_facts(self) -> tuple[str | None, bool, bool]:
        """(gateway address or None, isolated-gateway mode, internal), read from the network Docker actually
        made, not from the compose file that asked for it (D-066)."""
        out = self._docker("network", "inspect", f"{self.project}_lab_net", "--format", "{{json .}}", check=False)
        try:
            network = json.loads(out.stdout)
        except json.JSONDecodeError:
            return None, False, False
        gateways = [c.get("Gateway") for c in network.get("IPAM", {}).get("Config") or [] if c.get("Gateway")]
        isolated = (network.get("Options") or {}).get(GATEWAY_MODE_OPTION) == "isolated"
        return (gateways[0] if gateways else None), isolated, network.get("Internal") is True

    def _inspect(self, container: str) -> dict | None:
        done = self._docker("inspect", container, check=False)
        try:
            records = json.loads(done.stdout)
            return records[0] if isinstance(records, list) and records else None
        except json.JSONDecodeError:
            return None

    def compose_config(self) -> dict:
        out = self._compose("config", "--format", "json")
        try:
            return json.loads(out.stdout)
        except json.JSONDecodeError:
            raise HarnessError("`docker compose config` did not print JSON") from None

    def preflight(self) -> dict:
        """Every preflight check; raises one HarnessError naming every failure. Returns a report."""
        problems = check_compose_config(self.compose_config(), self.variant)
        gateway, isolated, internal = self.network_facts()
        if not isolated:
            problems.append("the lab network was not created in isolated-gateway mode (D-066)")
        if not internal:
            problems.append("the lab network Docker created is not internal")
        for service, container in (("attacker", self.attacker), ("target", self.target)):
            problems += check_live_container(self._inspect(container), service, self.variant, self.project)
        probe = (ROOT / "harness" / "network_probe.py").read_bytes()
        done = self._exec(self.attacker, "python3", "-", gateway or "", user="agent", input=probe,
                          check=False, timeout=180)
        try:
            report = json.loads(done.stdout)
        except json.JSONDecodeError:
            report = None
            problems.append(f"network probe: no JSON report (exit {done.returncode}): {_text(done.stderr)[:200]}")
        if report is not None:
            problems += evaluate_probe(report, gateway, isolated)
        if problems:
            raise HarnessError("preflight failed: " + "; ".join(problems))
        return {"gateway": gateway, "isolated": isolated, "internal": internal, "probe": report}

    # --- seeding and readiness --------------------------------------------------------------

    def seed(self, seed: dict) -> None:
        """The seed holds the flag and the admin password: stdin only (D-041)."""
        done = self._exec(self.target, "python", "seed_loader.py", user=TARGET_UID,
                          input=json.dumps(seed).encode("utf-8"), check=False)
        if done.returncode != 0:
            raise HarnessError(f"seeding failed (exit {done.returncode}): {_text(done.stderr)[:200]}")

    def health(self, attempts: int = 1) -> bool:
        """The target is running and its port accepts a TCP connection. TCP only, never HTTP: an HTTP
        request would be a logged event, and one before `started_at` fails validation (D-029, D-041).

        The target is single-threaded with a short idle timeout, so an agent that holds many idle connections
        can make one probe time out while the target is fine. `attempts` > 1 gives it the time to drain before
        the target is called down."""
        for attempt in range(attempts):
            done = self._exec(self.target, "python", "-c",
                              "import socket; socket.create_connection(('127.0.0.1', 8080), 3).close()",
                              check=False, timeout=20)
            if done.returncode == 0:
                return True
            if attempt + 1 < attempts:
                time.sleep(2)
        return False

    def attacker_running(self) -> bool:
        done = self._docker("inspect", "--format", "{{.State.Running}}", self.attacker, check=False)
        return _text(done.stdout) == "true"

    def wait_ready(self, timeout: float = READY_TIMEOUT_S) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.health():
                return
            time.sleep(0.25)
        raise HarnessError("the target never started listening after seeding")

    def verify_fresh_state(self, seed: dict) -> dict:
        """A second run starts from a verified clean state (PLAN.md phase 4 done-when): the database holds
        exactly the seed's rows and the attacker's home directory is empty."""
        cfg = seed["variant_config"]
        script = (
            "import json, sqlite3\n"
            "c = sqlite3.connect('file:/run/db/app.db?mode=ro', uri=True)\n"
            f"print(json.dumps([c.execute('SELECT count(*) FROM {cfg['items_table']}').fetchone()[0],"
            f" c.execute('SELECT count(*) FROM {cfg['users_table']}').fetchone()[0]]))\n"
        )   # table names were validated as plain identifiers by seed.validate_seed
        done = self._exec(self.target, "python", "-c", script, check=False)
        expected = [len(ITEMS), 1 + len(DECOY_USERNAMES)]
        try:
            counts = json.loads(done.stdout)
        except json.JSONDecodeError:
            raise HarnessError(f"could not read the seeded row counts: {_text(done.stderr)[:200]}") from None
        if counts != expected:
            raise HarnessError(f"the database holds {counts} (items, users) rows, the seed has {expected}")
        home = self._exec(self.attacker, "ls", "-A", "/home/agent", user="agent", check=False)
        if home.returncode != 0 or _text(home.stdout):
            raise HarnessError("the attacker's home directory is not empty before the run")
        return {"items": counts[0], "users": counts[1], "admin": ADMIN_USERNAME}

    # --- the clock (D-037) --------------------------------------------------------------------

    def measure_clock(self, samples: int = CLOCK_SAMPLES) -> tuple[float, float]:
        """(offset_ms, uncertainty_ms): the target container's clock minus the host's, by the median of
        several `docker exec ... date` round trips. The host reading is time.time_ns(), the same wall
        clock the step times come from (PLAN.md phase 4, dependency 5)."""
        readings = []
        for _ in range(samples):
            before = time.time_ns()
            done = self._exec(self.target, "date", "+%s%N", check=False, timeout=20)
            after = time.time_ns()
            if done.returncode != 0 or not _text(done.stdout).isdigit():
                raise HarnessError(f"could not read the target's clock: {_text(done.stderr)[:200]}")
            readings.append((before, after, int(_text(done.stdout))))
        return clock_offset(readings)

    @staticmethod
    def check_offset(offset_ms: float) -> None:
        problems = check_clock(offset_ms)
        if problems:
            raise HarnessError("; ".join(problems))

    # --- the end of a run -----------------------------------------------------------------------

    def _exit_code(self, container: str) -> int | None:
        done = self._docker("inspect", "--format", "{{.State.Running}} {{.State.ExitCode}}", container, check=False)
        parts = _text(done.stdout).split()
        if len(parts) != 2 or parts[0] == "true":
            return None
        return int(parts[1])

    def stop_attacker(self) -> int | None:
        """Stop everything the agent started, before ended_at and before the log is read (D-037)."""
        self._docker("stop", "-t", "3", self.attacker, check=False, timeout=60)
        if self.attacker_running():
            self._docker("kill", self.attacker, check=False, timeout=60)
            if self.attacker_running():
                raise HarnessError("the attacker could not be stopped, so its processes may still touch the target")
        return self._exit_code(self.attacker)

    def target_exit_code(self) -> int | None:
        """None while the target is still running: a code means it died during the run."""
        return self._exit_code(self.target)

    def stop_target(self) -> int | None:
        self._docker("stop", "-t", "5", self.target, check=False, timeout=60)
        return self._exit_code(self.target)

    def collect_events(self) -> tuple[list[dict], dict]:
        """The run's target events from its own (stopped) container, complete and in order.

        The log goes straight to a file in the run's own directory (not memory, and not the system temp
        directory: it can hold passwords the agent tried), and a log over MAX_LOG_BYTES fails the run
        without being read (D-042 item 3: the target's log has no rotation, so its growth is bounded here,
        after the fact, and only by what the disk holds). `docker logs` returns a long line whole (checked:
        a 100 KB line comes back as one line), so no reassembly is needed; the seq check is what proves
        nothing is missing (D-037)."""
        scratch = (self.work_dir or ROOT / "runs") / f".target-log-{self.run_id}"
        try:
            done = self._docker("logs", self.target, timeout=300, stdout_to=scratch)
            size = scratch.stat().st_size
            if size > MAX_LOG_BYTES:
                raise HarnessError(f"the target's log is {size // 2 ** 20} MiB, over the {MAX_LOG_BYTES // 2 ** 20} MiB limit: "
                                   "the agent flooded it, and the run's events were not read")
            data = scratch.read_bytes()
        finally:
            scratch.unlink(missing_ok=True)
        try:
            events = collect_events(data.decode("utf-8"), self.run_id)
        except (UnicodeDecodeError, ValueError) as err:
            raise HarnessError(f"the target's log could not be read as events: {err}") from None
        if [e.get("seq") for e in events] != list(range(1, len(events) + 1)):
            raise HarnessError("the target's log has a gap or a repeat in `seq`: the log is incomplete")
        return events, {"events": len(events), "log_bytes": size, "target_stderr_bytes": len(done.stderr)}

    # --- facts for the manifest -----------------------------------------------------------------

    def image_digests(self) -> dict[str, str]:
        """The image id of each running container: what actually ran, not what a tag points at now."""
        digests = {}
        for service, container in (("attacker", self.attacker), ("target", self.target)):
            done = self._docker("inspect", "--format", "{{.Image}}", container)
            digests[service] = _text(done.stdout)
        return digests

    def docker_version(self) -> str:
        return _text(self._docker("version", "--format", "{{.Server.Version}}").stdout)
