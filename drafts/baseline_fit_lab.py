"""Hold a seeded baseline lab open so you can measure sqlmap's fit in it by hand (D-089's build-time check).

This only brings the lab up, seeds it, and tears it down; it runs no attack. You run sqlmap yourself, in the
attacker container, from another terminal, then come back here and press Enter. Before tearing down it prints what
the measurement needs: whether the attacker was OOM-killed, how much of its home the run used, and how many lines the
target logged.

    .venv/Scripts/python drafts/baseline_fit_lab.py [A|B|C|D]     (default B)

It takes the harness's lock for as long as it runs (so a sweep or a run cannot remove the stack under you), and it
refuses to start while another harness process holds it. Ctrl+C also tears the stack down.
"""
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "harness"))
sys.path.insert(0, str(ROOT / "target"))

from lab import Lab  # noqa: E402
from run import new_seed, run_lock  # noqa: E402


def main() -> int:
    variant = sys.argv[1] if len(sys.argv) > 1 else "B"
    with run_lock(), tempfile.TemporaryDirectory() as scratch:
        lab = Lab(variant, uuid.uuid4().hex, baseline=True)
        lab.work_dir = Path(scratch)
        try:
            lab.up()
            lab.preflight()                      # the same checks an agent run gets, on the baseline image
            seed = new_seed(variant)
            lab.seed(seed)
            lab.wait_ready()
            cfg = seed["variant_config"]
            print(f"\nvariant {variant} is up and seeded. Attacker container: {lab.attacker}")
            print("Target, from inside the lab:  http://target:8080")
            print(f"Injectable path and parameter: {cfg['injectable_path']}  ?{cfg['injectable_param']}=")
            print("Run sqlmap there as the agent user:  docker exec --user agent <container> sqlmap ...")
            print("Watch it from another terminal:       docker stats <container>")
            input("\nPress Enter when sqlmap has finished (or you have stopped it) to read the results and tear down... ")

            state = lab._inspect(lab.attacker)["State"]
            print(f"\nattacker state: status={state['Status']} OOMKilled={state['OOMKilled']} exit={state['ExitCode']}")
            home = lab._exec(lab.attacker, "bash", "-c", "du -sk ~ | cut -f1; df -k ~ | tail -1", user="agent", check=False)
            used, filesystem = (home.stdout.decode().strip().splitlines() + ["?", "?"])[:2]
            print(f"attacker home: {used} KiB used; filesystem row: {filesystem}")
            # The kernel's own high-water marks for the container's cgroup (v2), so nobody has to catch a peak by eye.
            cg = lab._exec(
                lab.attacker, "bash", "-c",
                "cd /sys/fs/cgroup 2>/dev/null || { echo 'no cgroup v2 files here'; exit 0; }; "
                "for f in memory.peak memory.current memory.max pids.peak pids.max memory.events cpu.stat cpu.max; do "
                "echo \"== $f\"; cat $f 2>&1; done",
                user="agent", check=False).stdout.decode()
            print("\ncgroup counters (memory in bytes; cpu.stat times in microseconds):\n" + cg)
            logs = subprocess.run(["docker", "logs", lab.target], capture_output=True, text=True)
            print(f"target log lines: {(logs.stdout + logs.stderr).count(chr(10))}")
        finally:
            left = lab.down()
            print(f"torn down; left over: {left or 'nothing'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
