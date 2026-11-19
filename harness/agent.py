"""The agent loop (PLAN.md phase 4; D-062 limits, D-063 turn handling, D-064 termination and timing).

Deliberately free of Docker and boto3: the model, the executor, the target-health probe, the clock and
the step sink are all passed in, so the scorer's dependencies are tested against fakes (PLAN.md
phase 4, "What the scorer silently depends on"). The loop owns the clock, so it, and nothing else,
decides what a step's `started_at` and `ended_at` mean:

  * a command step is stamped around `executor.run` (the tool execution, never the model call);
  * a step that runs no tool (malformed, text-only, `submit_flag`) takes both times at the moment the
    model's reply was received.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from execution import Executor
from model import REQUEST_REJECTED, ModelClient, ModelError, ModelReply
from prompt_set import Prompts, find_leaks

# D-062
STEP_CAP = 30
CONTEXT_CEILING = 100_000
RESULT_ALLOWANCE = 2731        # 8 KiB at a conservative 3 bytes per token: the most one result can add
INFERENCE_CONFIG = {"temperature": 1.2, "top_p": 0.9, "max_tokens": 5000}

# D-083: a text-only turn is nudged with Prompts.continue_nudge instead of ending the run, up to this
# many CONSECUTIVE text-only turns; the one that reaches the limit ends it as agent_stopped, same as
# every text-only turn did before this entry. Resets to zero on any turn that is not text-only. Provider
# blocks are a separate, unconditional stop (D-075's R3; never nudged -- D-083 only concerns the model's
# own end_turn/stop_sequence, not a platform's decision).
TEXT_ONLY_LIMIT = 4

TOOL_ARGUMENT = {"run_command": "command", "submit_flag": "flag"}
PROVIDER_BLOCKS = ("guardrail_intervened", "content_filtered")


@dataclass(frozen=True)
class Limits:
    step_cap: int = STEP_CAP
    context_ceiling: int = CONTEXT_CEILING
    result_allowance: int = RESULT_ALLOWANCE
    text_only_limit: int = TEXT_ONLY_LIMIT


@dataclass
class LoopResult:
    termination_reason: str
    api_retries: int
    started_at: datetime                      # just before the first model call (D-029)
    detail: str | None = None                 # what went wrong, for api_error and harness_error
    error_kind: str | None = None             # for a failed model call: service, model_error or request_rejected (D-065)
    first_secret_step: dict[str, int] = field(default_factory=dict)   # secret name -> first step whose tool result held it
    steps: list[dict] = field(default_factory=list)


@dataclass
class Turn:
    """What one model reply is, before anything is run (D-063)."""
    kind: str                       # run_command | submit_flag | malformed | text_only | provider_block | window_exceeded
    cause: str | None = None        # the tool_call_error, when malformed
    tool_use: dict | None = None    # the single well-formed call


def classify_turn(reply: ModelReply) -> Turn:
    """Total over every stop reason. A turn is valid exactly when the stop reason is tool_use, there is
    exactly one tool call, its name is known and its arguments are exactly {command: str} or
    {flag: str}: nothing is coerced, stripped or unwrapped (D-063)."""
    if reply.stop_reason in PROVIDER_BLOCKS:
        return Turn("provider_block")
    if reply.stop_reason == "model_context_window_exceeded":
        return Turn("window_exceeded")
    if not reply.content:
        # An empty assistant message cannot be added to a Converse history, and answering it would
        # need harness text the model has not been shown before: it ends the run like any text-only turn.
        return Turn("text_only")
    calls = reply.tool_uses
    if reply.stop_reason in ("end_turn", "stop_sequence") and not calls:
        return Turn("text_only")
    if reply.stop_reason != "tool_use":          # max_tokens, malformed_*, or a tool call beside end_turn
        return Turn("malformed", "unusable_output")
    if not calls:
        return Turn("malformed", "unusable_output")
    if len(calls) > 1:
        return Turn("malformed", "multiple_calls")
    call = calls[0]
    name, arguments = call.get("name"), call.get("input")
    if name not in TOOL_ARGUMENT:
        return Turn("malformed", "unknown_tool")
    key = TOOL_ARGUMENT[name]
    if (not isinstance(arguments, dict) or set(arguments) != {key} or not isinstance(arguments[key], str)
            or (name == "run_command" and not _can_be_argv(arguments[key]))):
        return Turn("malformed", "invalid_arguments")
    return Turn(name, tool_use=call)


def _can_be_argv(command: str) -> bool:
    """A command can be run only if it can be one argv element: no NUL, and valid Unicode (a lone surrogate such as
    code point U+D800, which JSON allows, cannot be encoded). Otherwise `docker exec` would raise and a model's choice of characters
    would end the run as a harness_error, which is investigated and replaced; it is a malformed turn instead (D-069)."""
    if "\x00" in command:
        return False
    try:
        command.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _iso(moment: datetime) -> str:
    return moment.isoformat()


def run_agent(*, model: ModelClient, executor: Executor, prompts: Prompts, condition: str, run_id: str,
              secrets: dict[str, str], inference: dict | None = None, limits: Limits = Limits(),
              clock: Callable[[], datetime], health: Callable[[], bool],
              on_step: Callable[[dict], None], result: LoopResult | None = None) -> LoopResult:
    """Run the loop. `result` may be created by the caller, just before this call, and is filled in as the
    run goes: if anything below raises (a failed docker call, a Ctrl+C), the caller still holds every
    step recorded so far and the run's true start, so the record can be finished and still validate."""
    inference = inference or INFERENCE_CONFIG
    system = prompts.system_text(condition)
    watched = {**secrets, "run_id": run_id}
    messages: list[dict] = [{"role": "user", "content": [{"text": prompts.opening}]}]
    result = result or LoopResult("harness_error", 0, started_at=clock())
    last_tokens = 0
    consecutive_text_only = 0     # D-083: resets on any turn that engages; the limit is on a streak

    while True:
        # The leak invariant (PLAN.md phase 4): the texts the harness itself writes into the request
        # must not hold a secret. Names only in the message, never the value.
        # Rebuilt each time, not once: "before each model call" means what the next request is
        # made of, whatever changed since the last one.
        leaked = find_leaks(prompts.harness_authored_texts(condition), watched)
        if leaked:
            result.detail = f"leak invariant: harness-authored request text contains {', '.join(leaked)}"
            return result
        try:
            reply = model.converse(system=system, messages=messages, tool_config=prompts.tool_config,
                                   inference=inference)
        except ModelError as err:
            result.api_retries += err.retries
            # A request Converse refuses is the harness's own bug, so it is a harness_error and is
            # investigated; every other failure is an api_error (D-064), tagged with its kind so the
            # phase 6 exclusion rule can tell the model's own unusable output from an outage (D-065).
            result.termination_reason = "harness_error" if err.kind == REQUEST_REJECTED else "api_error"
            result.detail = f"{err.kind}: {err}"
            result.error_kind = err.kind
            return result
        result.api_retries += reply.retries
        received_at = clock()
        turn = classify_turn(reply)
        number = len(result.steps) + 1

        step = {
            "schema_version": "1", "run_id": run_id, "step": number,
            "started_at": _iso(received_at), "ended_at": _iso(received_at),
            "assistant_text": reply.text, "tool_name": None, "tool_input": None,
            "output_full": None, "output_sent_to_model": None, "truncated": False,
            "exit_code": None, "timed_out": False, "stop_reason": reply.stop_reason,
            "input_tokens": reply.input_tokens, "output_tokens": reply.output_tokens,
        }
        if reply.request_id:
            step["bedrock_request_id"] = reply.request_id
        if reply.raw_stop_reason is not None:
            step["raw_stop_reason"] = reply.raw_stop_reason
        if reply.raw_completion is not None:
            step["raw_completion"] = reply.raw_completion

        next_user_message: dict | None = None
        ran_command = False
        if turn.kind == "malformed":
            text = prompts.error_text(turn.cause)
            step.update(tool_call_error=turn.cause, output_sent_to_model=text,
                        raw_tool_use=[block for block in reply.content if "toolUse" in block])
            next_user_message = _answer_every_call(reply, text)
        elif turn.kind == "submit_flag":
            # Recorded exactly as sent. The reply is one fixed string whatever was submitted (D-001).
            step.update(tool_name="submit_flag", tool_input=turn.tool_use["input"],
                        output_full=prompts.submit_reply, output_sent_to_model=prompts.submit_reply)
        elif turn.kind == "run_command":
            ran_command = True
            command = turn.tool_use["input"]["command"]
            began = clock()
            outcome = executor.run(command)
            ended = clock()
            sent = outcome.output_sent or prompts.empty_output_notice
            step.update(started_at=_iso(began), ended_at=_iso(ended), tool_name="run_command",
                        tool_input=turn.tool_use["input"], output_full=outcome.output_full,
                        output_sent_to_model=sent, truncated=outcome.truncated,
                        exit_code=outcome.exit_code, timed_out=outcome.timed_out)
            for name, value in watched.items():
                if value in sent:
                    result.first_secret_step.setdefault(name, number)
            next_user_message = {"role": "user", "content": [{"toolResult": {
                "toolUseId": turn.tool_use["toolUseId"], "content": [{"text": sent}]}}]}

        last_tokens = reply.input_tokens + reply.output_tokens

        # What ends a run, in D-064's order; the first that applies wins. So a text-only turn on the
        # last step is a step_cap, and a text-only turn on a full context is a context_limit -- resolved
        # BEFORE the step is appended and sent to on_step, so a step can never claim a nudge that
        # step_cap or context_limit actually preempted. A nudge (D-083) sets the step's own fields here,
        # the same way a malformed turn's fixed error text does. Provider blocks are their own branch,
        # split from text_only (D-075's R3): a platform decision is never nudged.
        terminated = True
        if turn.kind == "submit_flag":
            result.termination_reason = "submitted"
        elif ran_command and not health():
            result.termination_reason = "target_down"
        elif number >= limits.step_cap:
            result.termination_reason = "step_cap"
        elif (turn.kind == "window_exceeded"
              or last_tokens + limits.result_allowance > limits.context_ceiling):
            result.termination_reason = "context_limit"
        elif turn.kind == "provider_block":
            result.termination_reason = "agent_stopped"
        elif turn.kind == "text_only":
            if not reply.content:
                # Structural, not policy: an empty assistant message cannot be carried into the next
                # request (see the comment where classify_turn makes this text_only), so this is
                # unconditional, the same as a provider block -- never nudged, whatever the limit is.
                result.termination_reason = "agent_stopped"
            else:
                consecutive_text_only += 1
                if consecutive_text_only < limits.text_only_limit:
                    terminated = False
                    text = prompts.continue_nudge
                    step.update(output_sent_to_model=text, nudged=True)
                    next_user_message = {"role": "user", "content": [{"text": text}]}
                else:
                    result.termination_reason = "agent_stopped"
        else:
            terminated = False
            consecutive_text_only = 0

        result.steps.append(step)
        on_step(step)
        if terminated:
            return result
        messages.append({"role": "assistant", "content": reply.content})
        messages.append(next_user_message)
        continue


def _answer_every_call(reply: ModelReply, text: str) -> dict:
    """The user turn that answers a malformed one. Converse expects a result for every tool call id,
    so each gets the same fixed text and the same (absent) status: the model learns nothing from the
    result that is not in `output_sent_to_model`. With no tool call to answer, it is a plain text turn."""
    results = [{"toolResult": {"toolUseId": call["toolUseId"], "content": [{"text": text}]}}
               for call in reply.tool_uses if call.get("toolUseId")]
    return {"role": "user", "content": results or [{"text": text}]}
