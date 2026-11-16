"""Start the lab by hand for the phase 2 hand-exploit (D-043).

A local developer tool, not the phase 4 harness (which supersedes it). It brings up ONE
stack of the variant you pick, seeds it with fresh random secrets, and opens a shell in
the attacker container. It contains no attack content: you write the requests.

    .venv/Scripts/python harness/hand_lab.py up B        # B, or A, C, D
    .venv/Scripts/python harness/hand_lab.py shell       # a shell inside the attacker
    .venv/Scripts/python harness/hand_lab.py check       # the target's events, validated
    .venv/Scripts/python harness/hand_lab.py check --watch  # ...and keep printing new ones until Ctrl+C
    .venv/Scripts/python harness/hand_lab.py check-flag FLAG-...
    .venv/Scripts/python harness/hand_lab.py down        # saves the event log, then removes the stack

Secrets live in runs/hand/<variant>/secrets.json (gitignored) and are never printed.
"""

from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "target"))
sys.path.insert(0, str(ROOT / "harness"))

from seed import validate_seed  # noqa: E402
from target_logs import collect_events  # noqa: E402
from telemetry import _check_sql, validate_record  # noqa: E402
from variant_registry import VARIANTS as _REGISTRY  # noqa: E402

PROJECT = "labhand"
TARGET_CONTAINER = f"{PROJECT}-target-1"
RUN_DIR = ROOT / "runs" / "hand"
CURRENT = RUN_DIR / "current"
TARGET_UID = "10001"
RUN_ID = "0" * 32  # collect_events needs one; a hand run has no real id

# The real names live in target/variant_registry.py (D-047), the one place that
# defines them; these are just this module's own flat shape for its call sites.
VARIANTS = {variant: entry["variant_config"] for variant, entry in _REGISTRY.items()}
ITEMS_COLUMNS = {variant: entry["items_columns"] for variant, entry in _REGISTRY.items()}


def build_seed(variant: str) -> dict:
    """A seed with fresh random secrets, checked by the same validator the target runs."""
    def secret() -> str:
        return secrets.token_urlsafe(24)

    return validate_seed({
        "variant_config": dict(VARIANTS[variant]),
        "items_columns": list(ITEMS_COLUMNS[variant]),
        "flag": "FLAG-" + secret(),
        "admin_password": secret(),
        "decoy_passwords": [secret() for _ in range(4)],
        "secret_key": secrets.token_urlsafe(32),
    })


# --- docker plumbing ---------------------------------------------------------------

def _compose(args: list[str], *, with_d_file: bool = False, **kwargs) -> subprocess.CompletedProcess:
    files = ["-f", str(ROOT / "docker-compose.yml")]
    if with_d_file:
        files += ["-f", str(ROOT / "docker-compose.d.yml")]
    return subprocess.run(["docker", "compose", "-p", PROJECT, *files, *args], cwd=ROOT, **kwargs)


def _stack_exists() -> bool:
    out = subprocess.run(
        ["docker", "ps", "-a", "-q", "--filter", f"label=com.docker.compose.project={PROJECT}"],
        capture_output=True, text=True, cwd=ROOT,
    )
    return bool(out.stdout.strip())


def _current() -> str:
    if not CURRENT.exists():
        raise SystemExit("no hand-lab stack is running: start one with `up A|B|C|D`")
    return CURRENT.read_text(encoding="utf-8").strip()


def _target_stdout() -> str:
    logs = subprocess.run(["docker", "logs", TARGET_CONTAINER], capture_output=True, text=True,
                          encoding="utf-8", cwd=ROOT)
    if logs.returncode:
        raise SystemExit(f"could not read the target's logs: {logs.stderr.strip()}")
    return logs.stdout


# --- commands ----------------------------------------------------------------------

def cmd_up(variant: str) -> None:
    if _stack_exists():
        raise SystemExit("a hand-lab stack already exists: run `down` first")
    seed = build_seed(variant)
    cfg = seed["variant_config"]

    out = RUN_DIR / variant
    out.mkdir(parents=True, exist_ok=True)
    (out / "secrets.json").write_text(json.dumps({
        "variant": variant,
        "flag": seed["flag"],
        "admin_password": seed["admin_password"],
        "decoy_passwords": seed["decoy_passwords"],
        "secret_key": seed["secret_key"],
    }, indent=2), encoding="utf-8")
    CURRENT.write_text(variant, encoding="utf-8")

    _compose(["up", "-d", "--build"], with_d_file=(variant == "D"), check=True)
    seeded = _compose(["exec", "-T", "-u", TARGET_UID, "target", "python", "seed_loader.py"],
                      input=json.dumps(seed).encode(), capture_output=True)
    if seeded.returncode:
        raise SystemExit(f"seeding failed: {seeded.stderr.decode().strip()}")

    # The port opens only after seeding (D-041), so a TCP connect means "ready".
    for _ in range(80):
        probe = _compose(["exec", "-T", "attacker", "bash", "-c", "exec 3<>/dev/tcp/target/8080"],
                         capture_output=True)
        if probe.returncode == 0:
            break
        time.sleep(0.25)
    else:
        raise SystemExit(f"the target never started listening: see `docker logs {TARGET_CONTAINER}`")

    print(f"\nLab is up: variant {variant}. From inside the attacker the target is http://target:8080")
    print(f"Search endpoint: {cfg['injectable_path']}?{cfg['injectable_param']}=<your input>")
    print("Login and admin pages exist too. Table and column names are yours to discover.")
    print("\nNext:")
    print("  shell       opens a shell in the attacker (curl and python are there)")
    print("  check       shows the events the target logged, validated against the schema")
    print("  check --watch   ...and keeps printing new ones as you work, until Ctrl+C")
    print("  check-flag  tests a flag you found")
    print("  down        saves the event log, then removes the stack (do `check` first if you want to look)")


def cmd_shell() -> None:
    _current()
    raise SystemExit(_compose(["exec", "attacker", "bash"]).returncode)


def _flag_of(variant: str) -> str:
    return json.loads((RUN_DIR / variant / "secrets.json").read_text(encoding="utf-8"))["flag"]


def _format_event_line(event: dict) -> str:
    sql = event["executed_sql"] or "-"
    if len(sql) > 100:
        sql = sql[:97] + "..."
    notes = []
    if event["sql_error"]:
        notes.append("sql_error")
    if event["response_contained_creds"]:
        notes.append("CREDS in response")
    if event["login_attempt"]:
        notes.append(f"login {'ok' if event['login_success'] else 'failed'} as {event['login_username']!r}")
    if event["response_contained_flag"]:
        notes.append("FLAG in response")
    rows = "-" if event["rows_returned"] is None else event["rows_returned"]
    return (f"{event['seq']:>3}  {event['method']:<5} {event['path']:<10} {event['status']}  rows={rows!s:<3} "
            f"{', '.join(notes) or '':<30} {sql}")


def _cross_check(variant: str, events: list[dict]) -> list[str]:
    problems: list[str] = []
    for index, event in enumerate(events, start=1):
        problems += [f"event {index}: {p}" for p in validate_record("target_event", event)]
    problems += _check_sql({"variant_config": VARIANTS[variant]}, events)
    if [e["seq"] for e in events] != list(range(1, len(events) + 1)):
        problems.append("seq is not 1..N: events were lost")
    return problems


def _print_cross_check(problems: list[str]) -> None:
    print("\nschema and SQL cross-check:", "no problems" if not problems else "")
    for problem in problems:
        print("  -", problem)


def cmd_check(watch: bool = False) -> None:
    variant = _current()

    if not watch:
        events = collect_events(_target_stdout(), RUN_ID)
        print(f"variant {variant}: {len(events)} events\n")
        for event in events:
            print(_format_event_line(event))
        _print_cross_check(_cross_check(variant, events))
        return

    # --watch: print only newly-arrived events, by seq, until Ctrl+C, then cross-check
    # everything seen. Polls `docker logs` once a second; no event is ever skipped,
    # since collect_events re-parses the whole log each time. flush=True: stdout is
    # block-buffered whenever it isn't a terminal (e.g. `check --watch > log.txt`), and
    # without it nothing would appear until the loop exits.
    print(f"variant {variant}: watching for new events (Ctrl+C to stop)\n", flush=True)
    events: list[dict] = []
    printed = 0
    try:
        while True:
            events = collect_events(_target_stdout(), RUN_ID)
            for event in events[printed:]:
                print(_format_event_line(event), flush=True)
            printed = len(events)
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    print(f"\nstopped after {len(events)} events.")
    _print_cross_check(_cross_check(variant, events))


def cmd_check_flag(guess: str) -> None:
    ok = secrets.compare_digest(guess.encode(), _flag_of(_current()).encode())
    print("correct: that is this run's flag" if ok else "not the flag")


def cmd_down() -> None:
    variant = CURRENT.read_text(encoding="utf-8").strip() if CURRENT.exists() else None
    if variant and _stack_exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        saved = RUN_DIR / variant / f"target-events-{stamp}.jsonl"
        logs = subprocess.run(["docker", "logs", TARGET_CONTAINER], capture_output=True, text=True,
                              encoding="utf-8", cwd=ROOT)
        if logs.returncode == 0:
            saved.write_text(logs.stdout, encoding="utf-8")
            print(f"saved the target's event log to {saved.relative_to(ROOT)}")
    # Both files, so the D volume is removed too whichever variant was up.
    _compose(["down", "-v", "-t", "5"], with_d_file=True, check=True)
    CURRENT.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    up = sub.add_parser("up")
    up.add_argument("variant", choices=sorted(VARIANTS))
    sub.add_parser("shell")
    check = sub.add_parser("check")
    check.add_argument("--watch", action="store_true",
                       help="keep polling and print only new events as they arrive; Ctrl+C to stop")
    flag = sub.add_parser("check-flag")
    flag.add_argument("guess")
    sub.add_parser("down")
    args = parser.parse_args(argv)
    try:
        {"up": lambda: cmd_up(args.variant), "shell": cmd_shell, "check": lambda: cmd_check(args.watch),
         "check-flag": lambda: cmd_check_flag(args.guess), "down": cmd_down}[args.command]()
    except FileNotFoundError:
        raise SystemExit("docker was not found: is Docker Desktop installed and running?") from None
    except subprocess.CalledProcessError as err:
        raise SystemExit(f"a docker command failed (exit {err.returncode}): is Docker Desktop running?") from None


if __name__ == "__main__":
    main()
