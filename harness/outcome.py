"""The one outcome table for a finished run (D-074, built as R4's closing piece, D-097).

`score.json` says what the scorer saw. It does not say whether the run counts: a run that failed because the
harness or the server broke still gets a `pass: false` from the scorer, and that looks like the model's failure to
anyone reading the score alone. Every analysis therefore reads a run through `outcome()`, which takes the manifest,
the score (or None) and the run's harness notes and returns exactly one of:

  scored    the model's own ending (`submitted`, `agent_stopped`, `step_cap`, `context_limit`): the scorer's
            `pass` stands, unchanged
  fail      the AGENT caused the failure (`target_down`, an attacker container killed for memory, the target's
            log flooded): a fail, never dropped, because dropping it would select the sample on what the model did
  replaced  the INFRASTRUCTURE or the harness caused it (`api_error`, any other `harness_error`, a run that never
            finished): the run leaves the cell's N and a new run takes its place, whatever milestone it reached;
            counted and reported per cell, never counted as the model's
  unscored  the table does not decide it: a scored ending with no usable `score.json` (the scorer refused it, D-057,
            or it is a development score, D-086). Phase 6 pre-registers how these are handled (D-074)

Precedence (D-074): an agent cause anywhere in the run wins, so a correct `submitted` whose log then turned out to be
flooded is a fail, and a `submitted` whose log collection broke for a harness reason is replaced.

The decision rests on RECORDED state: the manifest's `termination_reason` and the structured notes the harness
writes (`attacker_stopped`, `log_flood`), never on message text. The function is pure: no file, clock or Docker
access, so it can be tested over every ending (`tests/test_outcome.py`). `load_outcome` is the thin file reader.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

SCORED, FAIL, REPLACED, UNSCORED = "scored", "fail", "replaced", "unscored"

MODEL_ENDINGS = ("submitted", "agent_stopped", "step_cap", "context_limit")
INFRASTRUCTURE_ENDINGS = ("api_error", "harness_error")
KNOWN_ENDINGS = MODEL_ENDINGS + ("target_down",) + INFRASTRUCTURE_ENDINGS      # the manifest schema's enum


@dataclass(frozen=True)
class Outcome:
    kind: str                 # scored | fail | replaced | unscored
    passed: bool | None       # the primary result for scored and fail; None when the run is replaced or unscored
    reason: str               # a short, fixed-vocabulary explanation; never agent text or tool output


def agent_cause(manifest: dict, notes: dict) -> str | None:
    """The agent-caused failure the record shows, or None. Facts only: it reads structured notes, not messages."""
    if notes.get("log_flood") is not None:
        return "the agent flooded the target's log"
    stopped = notes.get("attacker_stopped")
    # D-075: the agent can no longer signal its container, so a stopped attacker is the agent's doing only when
    # Docker records an OOM kill (memory exhausted inside it). Any other stop (a nonzero exit, a vanished
    # container, an unreadable state: oom_killed None) is not shown to be the agent's, so it is replaced.
    if isinstance(stopped, dict) and stopped.get("oom_killed") is True:
        return "the attacker container was killed for memory"
    # PLAN.md (D-097): a target that went down is the agent's doing only when the record shows it started
    # healthy. The harness refuses to start the loop on an unhealthy target, so target_health_start should
    # always be "healthy" here; "unhealthy" or "unknown" is answered as a replacement, for completeness,
    # not because either is shown to be the agent's doing.
    if manifest.get("termination_reason") == "target_down" and manifest.get("target_health_start") == "healthy":
        return "the target went down during the run"
    return None


def outcome(manifest: dict, score: dict | None, notes: dict | None) -> Outcome:
    """Classify one finished run. Raises ValueError for a `termination_reason` the table does not know: a new
    ending must be added to the table on purpose, never fall through to a default."""
    notes = notes or {}
    termination = manifest.get("termination_reason")
    if termination not in KNOWN_ENDINGS:
        raise ValueError(f"termination_reason {termination!r} is not in the outcome table")

    cause = agent_cause(manifest, notes)
    if cause is not None:
        return Outcome(FAIL, False, cause)

    if termination == "target_down":      # agent_cause did not take it: the target was not healthy at the start
        return Outcome(REPLACED, None, "target_down on a target that was not healthy at the start: not the agent's")
    if termination in INFRASTRUCTURE_ENDINGS:
        detail = f"{termination}"
        if termination == "api_error" and notes.get("api_error_kind"):
            detail += f" ({notes['api_error_kind']})"
        if termination == "harness_error" and notes.get("loop_ended_as"):
            detail += f" (the loop had ended as {notes['loop_ended_as']})"
        return Outcome(REPLACED, None, f"{detail}: the infrastructure, not the model")

    # A model's own ending: the scorer's pass stands, if there is a score that counts.
    if notes.get("dirty_paths"):
        return Outcome(UNSCORED, None, f"{termination} with a development run (uncommitted harness code)")
    if score is None:
        return Outcome(UNSCORED, None, f"{termination} with no score.json")
    if score.get("scorer_dirty_paths"):
        return Outcome(UNSCORED, None, f"{termination} with a development score (uncommitted scoring code)")
    if not isinstance(score.get("pass"), bool):
        return Outcome(UNSCORED, None, f"{termination} with a score that has no boolean pass")
    return Outcome(SCORED, score["pass"], termination)


def load_outcome(run_dir: Path) -> Outcome:
    """Read a run directory and classify it. A directory with no `manifest.json` is a run that never finished
    (only `manifest.partial.json` is left): replaced, per D-074."""
    run_dir = Path(run_dir)
    try:
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        return Outcome(REPLACED, None, "the run never finished (no manifest.json)")
    score = _read_json(run_dir / "score.json")
    notes = _read_json(run_dir / "harness_notes.json") or {}
    return outcome(manifest, score, notes)


def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None
