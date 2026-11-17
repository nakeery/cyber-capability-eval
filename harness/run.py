"""Run one evaluation trial end to end and write its run directory (PLAN.md phase 4).

    .venv/Scripts/python harness/run.py build                 # build the two images (once, and after any change)
    .venv/Scripts/python harness/run.py run B no_hint         # one trial: variant A|B|C|D, condition no_hint|hint
    .venv/Scripts/python harness/run.py sweep                 # remove leftover lab stacks; list crashed runs

A run directory under runs/<run_id>/ (gitignored: it holds the run's flag and password):
    manifest.json         the run manifest, written once, atomically, at the end
    manifest.partial.json written BEFORE the stack comes up, removed when manifest.json exists: if a
                          run is killed, this is the only record that it happened (and holds its secrets)
    steps.jsonl           one step per line, appended and flushed as each step completes
    target_events.jsonl   the target's events, from its own stopped container
    harness_notes.json    everything that has no schema: preflight results, leak-scan timing, sweeps,
                          termination detail, validation problems, development-run flags
    score.json            the scorer's verdict, if the scoring code is committed and clean

`execute_run` takes the lab, the model and the clock as arguments, so tests drive it with fakes.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import traceback
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "harness"))
sys.path.insert(0, str(ROOT / "target"))

from agent import INFERENCE_CONFIG, Limits, LoopResult, run_agent  # noqa: E402
from execution import DockerExecutor  # noqa: E402
from lab import HarnessError, Lab  # noqa: E402
from model import ModelClient  # noqa: E402
from local_model import ServerCheckError, verify_weights  # noqa: E402
from prompt_set import Prompts, find_leaks, load_prompts  # noqa: E402
from seed import validate_seed  # noqa: E402
from variant_registry import VARIANTS  # noqa: E402

RUNS_DIR = ROOT / "runs"
LOCK_NAME = ".lab.lock"
UNKNOWN_DIGEST = "sha256:" + "0" * 64    # a run that failed before `up` has no image to name
HEALTH_ATTEMPTS = 4                      # a health probe is retried this many times before the target is called down
# What a run's behavior depends on: if any of it differs from the commit, the commit is false provenance.
HARNESS_CODE = ("harness", "prompts", "schemas", "scoring", "target", "attacker", "docker-compose.yml",
                "docker-compose.d.yml", "requirements.txt")


def new_seed(variant: str) -> dict:
    """A fresh seed for one run, checked by the same validator the target applies (D-041, D-042)."""
    entry = VARIANTS[variant]
    config = dict(entry["variant_config"])
    # D-042 item 5: the planted flag file exists in D and nowhere else.
    assert ("shortcut_path" in config) == (variant == "D"), "shortcut_path must exist exactly in variant D"
    return validate_seed({
        "variant_config": config,
        "items_columns": list(entry["items_columns"]),
        "flag": "FLAG-" + secrets.token_urlsafe(24),
        "admin_password": secrets.token_urlsafe(24),
        "decoy_passwords": [secrets.token_urlsafe(24) for _ in range(4)],
        "secret_key": secrets.token_urlsafe(32),     # 43 characters: 256 random bits (D-042)
    })


def git_provenance(root: Path = ROOT) -> tuple[str, list[str]]:
    """(HEAD's hash, the code paths that differ from it). A dirty path means the commit does not describe
    what ran."""
    def git(*args: str) -> str:
        done = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, encoding="utf-8")
        if done.returncode != 0:
            raise HarnessError(f"git {args[0]} failed: {done.stderr.strip()[:200]}")
        # Only the trailing newline goes: porcelain lines start with a status column that can be a space
        # (" M path"), and a full strip() would eat it and cut a character off the first path.
        return done.stdout.rstrip("\n")

    dirty = [line[3:] for line in git("status", "--porcelain", "--", *HARNESS_CODE).splitlines()]
    return git("rev-parse", "HEAD").strip(), dirty


@contextmanager
def run_lock(runs_dir: Path = RUNS_DIR):
    """One harness at a time: the sweep removes every lab stack, so a second harness would remove the
    first one's. A stale lock from a crash is removed by hand, deliberately."""
    runs_dir.mkdir(parents=True, exist_ok=True)
    path = runs_dir / LOCK_NAME
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        raise HarnessError(f"{path} exists: another harness is running, or one crashed (then delete it)") from None
    try:
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        yield
    finally:
        path.unlink(missing_ok=True)


def find_orphans(runs_dir: Path = RUNS_DIR) -> list[str]:
    """Runs that began but never wrote a manifest: crashed or killed. They are reported, never silently re-run."""
    if not runs_dir.is_dir():
        return []
    return sorted(d.name for d in runs_dir.iterdir()
                  if (d / "manifest.partial.json").exists() and not (d / "manifest.json").exists())


def _write_json(path: Path, record: object) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="\n")
    os.replace(tmp, path)     # atomic: a reader never sees half a manifest


@dataclass
class RunState:
    """What is learned along the way; the manifest is assembled from it at the end."""
    docker_version: str = "unknown"
    digests: dict = field(default_factory=lambda: {"attacker": UNKNOWN_DIGEST, "target": UNKNOWN_DIGEST})
    offset_ms: float | None = None
    uncertainty_ms: float | None = None
    offset_end_ms: float | None = None
    health_start: str = "unknown"
    health_end: str = "unknown"
    exit_codes: dict = field(default_factory=lambda: {"attacker": None, "target": None})
    loop: object = None
    error: str | None = None
    failed_at: datetime | None = None
    ended_at: datetime | None = None
    events: list = field(default_factory=list)
    up: bool = False


def execute_run(*, variant: str, condition: str, lab: Lab, model: ModelClient, prompts: Prompts, runs_dir: Path,
                clock: Callable[[], datetime], harness_commit: str, dirty_paths: list[str] = (),
                order_seed: int = 0, executor_factory: Callable | None = None,
                score_fn: Callable[[Path], tuple[dict, list[str]]] | None = None, seed: dict | None = None,
                limits: Limits = Limits()) -> Path:
    run_id = lab.run_id
    seed = seed or new_seed(variant)
    run_dir = runs_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    lab.work_dir = run_dir     # the target's log is written here while it is read, never to the system temp directory
    notes: dict = {"dirty_paths": list(dirty_paths)}
    state = RunState()
    make_executor = executor_factory or (lambda l: DockerExecutor(
        l.attacker, marker=prompts.truncation_marker, notice=prompts.timeout_notice))

    # The secrets reach disk before anything starts, so a killed run still leaves its flag behind.
    _write_json(run_dir / "manifest.partial.json", {
        "run_id": run_id, "variant": variant, "condition": condition, "harness_commit": harness_commit,
        "flag": seed["flag"], "admin_password": seed["admin_password"], "begun_at": clock().isoformat()})

    steps_file = open(run_dir / "steps.jsonl", "a", encoding="utf-8", newline="\n")

    def write_step(step: dict) -> None:
        steps_file.write(json.dumps(step) + "\n")
        steps_file.flush()

    interrupted: BaseException | None = None
    try:
        try:
            if model.backend == "local":
                # Before any Docker work: a server that is not the pinned one ends the run with nothing to clean up.
                # The rendered prefix is what the model will be shown, so the leak scan runs on THAT (D-060).
                try:
                    prepared = model.prepare(prompts.system_text(condition), prompts.tool_config, prompts.opening)
                    # The file the SERVER was started with (read from its process), not one named in a config: hash that.
                    if prepared.get("weights_path"):
                        verify_weights(Path(prepared.pop("weights_path")), model.pin.weights_sha256)
                except ServerCheckError as err:
                    raise HarnessError(str(err)) from None
                leaked = find_leaks([prepared.pop("rendered_prefix")], {"flag": seed["flag"], "admin_password": seed["admin_password"],
                                                                       "secret_key": seed["secret_key"], "run_id": run_id})
                if leaked:
                    raise HarnessError(f"leak invariant: the rendered local request contains {', '.join(leaked)}")
                notes["local_server"] = prepared
            state.docker_version = lab.docker_version()
            notes["swept"] = lab.sweep()
            lab.assert_clean()
            notes["free_bytes"] = lab.check_disk()
            lab.up()
            state.up = True
            state.digests = lab.image_digests()
            notes["preflight"] = lab.preflight()
            lab.seed(seed)
            lab.wait_ready()
            notes["fresh_state"] = lab.verify_fresh_state(seed)
            state.offset_ms, state.uncertainty_ms = lab.measure_clock()
            lab.check_offset(state.offset_ms)
            if not lab.health():
                raise HarnessError("the target is not healthy at the start of the run")
            state.health_start = "healthy"

            def health() -> bool:
                # After every command: first the attacker (a dead or wedged one would otherwise show up as
                # ordinary steps full of Docker's own error text, which the model must never be shown), then
                # the target, retried because a single refused connection from a busy single-threaded server
                # is not an outage (D-065).
                if not lab.attacker_running():
                    raise HarnessError("the attacker container is not running")
                return lab.health(attempts=HEALTH_ATTEMPTS)

            # Created before the loop and handed in, so that if the loop raises, the steps already written
            # and the run's true start are still known and the log is still collected.
            state.loop = LoopResult("harness_error", 0, started_at=clock())
            run_agent(
                model=model, executor=make_executor(lab), prompts=prompts, condition=condition, run_id=run_id,
                secrets={"flag": seed["flag"], "admin_password": seed["admin_password"],
                         "secret_key": seed["secret_key"]},
                inference=INFERENCE_CONFIG, limits=limits, clock=clock, health=health, on_step=write_step,
                result=state.loop)
        except (Exception, KeyboardInterrupt) as err:
            state.failed_at = clock()
            if isinstance(err, KeyboardInterrupt):
                interrupted = err
            state.error = str(err) if isinstance(err, HarnessError) else f"{type(err).__name__}: {err}"
            if not isinstance(err, HarnessError):
                notes["traceback"] = traceback.format_exc()
        _finish(lab, state, notes, clock)
    finally:
        steps_file.close()
        try:
            notes["left_after_down"] = lab.down()
        except (Exception, KeyboardInterrupt) as err:     # teardown must never hide the run's own record
            notes["down_error"] = f"{type(err).__name__}: {err}"
            if isinstance(err, KeyboardInterrupt) and interrupted is None:
                interrupted = err       # a second Ctrl+C during teardown: write the record, then propagate it

    _write_run(run_dir, state, notes, variant=variant, condition=condition, seed=seed, model=model,
               prompts=prompts, harness_commit=harness_commit, order_seed=order_seed, limits=limits,
               run_id=run_id)
    if score_fn is not None:
        try:
            score, score_notes = score_fn(run_dir)
            notes["score"] = {"pass": score["pass"], "milestones": score["milestones"], "notes": score_notes}
        except Exception as err:
            notes["score_error"] = f"{type(err).__name__}: {err}"
    _write_json(run_dir / "harness_notes.json", notes)
    (run_dir / "manifest.partial.json").unlink(missing_ok=True)
    if interrupted is not None:
        raise interrupted
    return run_dir


def _finish(lab: Lab, state: RunState, notes: dict, clock: Callable[[], datetime]) -> None:
    """The end of a run, in the order the decisions require. Each step is guarded on its own: one failing
    must not skip the rest, and every failure is kept (the first becomes the harness_error)."""
    problems: list[str] = []

    def attempt(label: str, action: Callable):
        try:
            return action()
        except Exception as err:
            problems.append(f"{label}: {err}")
            return None

    if state.up:
        # D-037: the attacker's processes stop before ended_at and before the log is read.
        state.exit_codes["attacker"] = attempt("stopping the attacker", lab.stop_attacker)
        state.health_end = "healthy" if attempt("final health check", lab.health) else "unhealthy"
    state.ended_at = clock()
    if state.up:
        # A target the agent crashed cannot be asked for its clock. That is not a harness failure (it would
        # turn a legitimate target_down into a harness_error that is investigated and never counted): the end
        # offset is null, which the schema allows, and the reason is noted.
        try:
            state.offset_end_ms = lab.measure_clock()[0]
        except Exception as err:
            notes["end_clock_unavailable"] = str(err)
        state.exit_codes["target"] = attempt("reading the target's exit code", lab.target_exit_code)
        attempt("stopping the target", lab.stop_target)
        if state.loop is not None:     # before the loop there can be no events, and the log is not needed
            collected = attempt("collecting the target log", lab.collect_events)
            if collected:
                state.events, log_notes = collected
                notes["log"] = log_notes
    if problems:
        notes["finish_problems"] = problems
        if state.error is None:
            state.error = "; ".join(problems)


def _write_run(run_dir: Path, state: RunState, notes: dict, *, variant: str, condition: str, seed: dict,
               model: ModelClient, prompts: Prompts, harness_commit: str, order_seed: int, limits: Limits,
               run_id: str) -> None:
    loop = state.loop
    termination = loop.termination_reason if loop else "harness_error"
    detail = loop.detail if loop else None
    if state.error:
        if loop and termination != "harness_error":
            state.error += f" (the loop had ended as {termination})"
            notes["loop_ended_as"] = termination          # structured, so an analysis need not parse the message
        termination, detail = "harness_error", state.error
    if termination != "harness_error" and detail:
        notes["termination_detail"] = detail
    if loop and termination == "api_error" and loop.error_kind:
        notes["api_error_kind"] = loop.error_kind
    if loop:
        notes["first_secret_step"] = loop.first_secret_step

    ended_at = state.ended_at
    started_at = loop.started_at if loop else (state.failed_at or ended_at)
    if started_at > ended_at:       # a failure noticed before the loop: the run has no window of its own
        started_at = ended_at
    manifest = {
        "schema_version": "1", "run_id": run_id, "redacted": False, "variant": variant,
        "variant_config": dict(seed["variant_config"]), "condition": condition, "prompt_variant_id": "original",
        "backend": model.backend, "model_id": model.model_id,
        "inference_config": dict(INFERENCE_CONFIG),
        "system_prompt_hash": prompts.system_prompt_hash(condition), "hint_text": prompts.hint_text(condition),
        "step_cap": limits.step_cap, "image_digests": state.digests, "harness_commit": harness_commit,
        "docker_version": state.docker_version, "run_order_seed": order_seed,
        "clock_offset_ms": state.offset_ms, "clock_uncertainty_ms": state.uncertainty_ms,
        "clock_offset_end_ms": state.offset_end_ms,
        "flag": seed["flag"], "admin_password": seed["admin_password"],
        "started_at": started_at.isoformat(), "ended_at": ended_at.isoformat(),
        "target_health_start": state.health_start, "target_health_end": state.health_end,
        "container_exit_codes": state.exit_codes, "api_retries": loop.api_retries if loop else 0,
        "termination_reason": termination, "harness_error": detail if termination == "harness_error" else None,
    }
    if model.backend == "bedrock":
        manifest["region"] = model.region
    else:
        manifest["local_runtime"] = model.local_runtime
    with open(run_dir / "target_events.jsonl", "w", encoding="utf-8", newline="\n") as handle:
        for event in state.events:
            handle.write(json.dumps(event) + "\n")
    _write_json(run_dir / "manifest.json", manifest)

    import telemetry
    notes["validation"] = telemetry.validate_run_dir(run_dir, include_score=False)
    drift = telemetry.clock_drift_ms(manifest)
    if drift is not None:
        notes["clock_drift_ms"] = drift


def build_local_model(seed: int | None):
    """The local client, and the Limits its window implies. The server is started by the operator (D-067), never by
    the harness; this checks the weights on disk against the pin and reads where to find the server from .env."""
    from local_model import LocalClient, LocalPin, local_settings
    url, key_file, pin_file = local_settings()
    if not key_file.is_file():
        raise HarnessError(f"no key file at {key_file} (set LOCAL_LLM_KEY_FILE in .env; see .env.example)")
    try:
        pin = LocalPin.from_file(pin_file) if pin_file else LocalPin.from_file()   # a different model is a different pin file
    except (OSError, ValueError, TypeError, ServerCheckError) as err:
        raise HarnessError(f"the local model is not ready: {err}") from None
    seed = secrets.randbits(31) if seed is None else seed
    client = LocalClient(url, key_file.read_text().strip(), pin, seed)
    # The window must hold the prompt AND the reply: the loop ends a run when the next prompt could leave less
    # than max_tokens of room (D-062 for Bedrock, D-060 for a local window).
    return client, Limits(context_ceiling=pin.context_length - INFERENCE_CONFIG["max_tokens"])


def default_score(run_dir: Path) -> tuple[dict, list[str]]:
    sys.path.insert(0, str(ROOT / "scoring"))
    from scorer import resolve_scorer_commit, score_run_dir
    return score_run_dir(run_dir, resolve_scorer_commit())


def summarize(run_dir: Path) -> str:
    """One screen of facts about a finished run. No agent text, no tool output, no secrets."""
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    notes = json.loads((run_dir / "harness_notes.json").read_text(encoding="utf-8"))
    steps = sum(1 for line in (run_dir / "steps.jsonl").read_text(encoding="utf-8").splitlines() if line.strip())
    lines = [f"run {manifest['run_id']}", f"  variant {manifest['variant']}, condition {manifest['condition']}, "
             f"model {manifest['model_id']}", f"  ended: {manifest['termination_reason']} after {steps} step(s)"]
    if manifest["harness_error"]:
        lines.append(f"  harness_error: {manifest['harness_error']}")
    if notes.get("termination_detail"):
        lines.append(f"  detail: {notes['termination_detail']}")
    if "score" in notes:
        lines.append(f"  score: pass={notes['score']['pass']}, milestones={notes['score']['milestones']}")
    if "score_error" in notes:
        lines.append(f"  not scored: {notes['score_error']}")
    problems = notes.get("validation") or []
    lines.append("  validation: " + ("ok" if not problems else f"{len(problems)} problem(s)"))
    lines += [f"    - {p}" for p in problems[:10]]
    if notes.get("clock_drift_ms") is not None:
        lines.append(f"  clock drifted {notes['clock_drift_ms']:.0f} ms during the run")
    if notes.get("dirty_paths"):
        lines.append(f"  DEVELOPMENT RUN: uncommitted changes in {', '.join(notes['dirty_paths'])}")
    if notes.get("left_after_down"):
        lines.append(f"  WARNING: lab resources survived teardown: {notes['left_after_down']}")
    if notes.get("down_error"):
        # `down` itself failed, so what survived was never counted: the attacker may still be running until the
        # next run's sweep (or `run.py sweep`) removes it.
        lines.append(f"  WARNING: teardown failed ({notes['down_error']}); lab resources may still be running")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("build")
    sub.add_parser("sweep")
    run = sub.add_parser("run")
    run.add_argument("variant", choices=sorted(VARIANTS))
    run.add_argument("condition", choices=["no_hint", "hint"])
    run.add_argument("--backend", choices=["bedrock", "local"], default="bedrock",
                     help="local is the evaluated model after D-067; it needs harness/local_pin.json and a running llama-server")
    run.add_argument("--model", choices=["micro", "pro"], default="micro", help="bedrock only: micro is the evaluated model of D-023")
    run.add_argument("--seed", type=int, default=None, help="local only: this run's sampling seed, recorded (default: random)")
    run.add_argument("--order-seed", type=int, default=0, help="the randomized block order's seed, recorded as run_order_seed")
    run.add_argument("--allow-dirty", action="store_true",
                     help="run with uncommitted code (a DEVELOPMENT run: recorded in harness_notes.json, never study data)")
    run.add_argument("--no-score", action="store_true")
    args = parser.parse_args(argv)

    try:
        with run_lock():
            if args.command == "build":
                Lab("B", uuid.uuid4().hex).build_images()
                print("images built")
                return 0
            if args.command == "sweep":
                print("removed:", Lab("B", uuid.uuid4().hex).sweep())
                orphans = find_orphans()
                print(f"runs that began and never finished: {orphans or 'none'}")
                return 0
            orphans = find_orphans()
            if orphans:
                print(f"note: {len(orphans)} earlier run(s) never finished (see `sweep`): {orphans}")
            commit, dirty = git_provenance()
            if dirty and not args.allow_dirty:
                print(f"refusing to run: uncommitted changes in {dirty}. Commit them, or pass --allow-dirty for a development run.")
                return 2
            limits = Limits()
            if args.backend == "local":
                model, limits = build_local_model(args.seed)
            else:
                from model import bedrock_from_env
                model = bedrock_from_env("NOVA_MICRO_MODEL_ID" if args.model == "micro" else "NOVA_PRO_MODEL_ID")
            run_dir = execute_run(
                variant=args.variant, condition=args.condition, lab=Lab(args.variant, uuid.uuid4().hex),
                model=model, prompts=load_prompts(), runs_dir=RUNS_DIR, clock=lambda: datetime.now(timezone.utc),
                harness_commit=commit, dirty_paths=dirty, order_seed=args.order_seed, limits=limits,
                score_fn=None if args.no_score else default_score)
            print(summarize(run_dir))
            return 0
    except HarnessError as err:
        print(f"harness error: {err}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
