"""What a recorded step IS, read from the step record alone (D-072 R3, D-075).

Two kinds of step look like the model's own text-only turn and are not:

  * a `model_context_window_exceeded` reply from the local server: the window was full, so the server refused and
    the client records a step with `tool_name: null`, no `tool_call_error` and EMPTY text. The run ends as
    `context_limit` (or `step_cap`, if that was the last step the cap allowed); the model wrote nothing. (A run also
    ends as `context_limit` when the harness's token estimate crosses its ceiling after an ORDINARY step: that
    step is the model's own, and this module has nothing to say about it.)
  * a `content_filtered` or `guardrail_intervened` reply from Bedrock: `assistant_text` holds the PLATFORM's
    "blocked by our content filters" message. The model wrote nothing there either (D-025, D-063).

A labeler that took either for the model's own words would count a text-only ending after a tool call, or a
refusal, that never happened. So everything that reads steps back (the `trajectory-analyst`, the pilot's counts)
asks this module instead of testing `tool_name is None` itself.

`step_kind` returns the same names the loop gave the turn (`agent.classify_turn`'s `Turn.kind`), and
tests/test_step_kind.py pins that for every stop reason against every content shape, so the two cannot drift.
"""

from __future__ import annotations

from agent import PROVIDER_BLOCKS

WINDOW_EXCEEDED_STOP = "model_context_window_exceeded"
# Steps whose `assistant_text` is not the model's writing: the platform's message, or nothing.
NOT_THE_MODELS_WORDS = ("provider_block", "window_exceeded")
# The stop reasons by which the model itself says it is finished (the loop's own text-only rule uses the same two).
MODEL_STOPS = ("end_turn", "stop_sequence")


def step_kind(step: dict) -> str:
    """One of run_command, submit_flag, malformed, text_only, provider_block, window_exceeded.

    Decided in the loop's own order: a platform block or a full window first (whatever else the step holds),
    then a tool call, then a malformed one (`tool_call_error`), and only what is left is a text-only turn."""
    stop = step.get("stop_reason")
    if stop in PROVIDER_BLOCKS:
        return "provider_block"
    if stop == WINDOW_EXCEEDED_STOP:
        return "window_exceeded"
    if step.get("tool_name") is not None:
        return step["tool_name"]
    if step.get("tool_call_error") is not None:
        return "malformed"
    return "text_only"


def models_own_words(step: dict) -> bool:
    """False for a step whose `assistant_text` is the platform's message or empty because the window was full:
    it can never be a refusal, and never a text-only turn by the model."""
    return step_kind(step) not in NOT_THE_MODELS_WORDS


def ends_text_only_after_a_command(steps: list[dict], termination_reason: str, *, attempts: bool = False) -> bool:
    """The run ENDED because the model stopped after having run a command (D-075's definition of the count).

    This is the count D-067's spike warned about: the model explaining instead of continuing. Under D-063 any
    text-only turn ended a run; under D-083 only the turn that makes `text_only_limit` consecutive text-only turns
    does (the earlier ones are nudged, `nudged: true`), and `hit_the_nudge_limit` below says which of these ended
    that way. All of these must hold:
      * the run's `termination_reason` is `agent_stopped`. The question the count answers is whether stopping
        cuts runs short, and a text-only turn on the last step the cap allowed, or on a window the harness
        judged full, ended the run anyway (`step_cap`, `context_limit`) and cost nothing;
      * its last step is a text-only turn that the MODEL ended: `stop_reason` is `end_turn` or `stop_sequence`. The
        loop calls ANY empty reply text-only, whatever the stop reason, but an empty reply with another stop reason
        (a `malformed_model_output` server state, say) is not the model deciding to stop;
      * an earlier step ran a command. `attempts=True` is the SECONDARY count, which also accepts an earlier
        malformed tool call (it too returned the harness's error text as a tool result): a model whose calls keep
        coming out malformed and then switches to prose is engaged and stopping mid-chain.

    The definition is fixed here so that it is not chosen after the floor check's data has been seen."""
    if termination_reason != "agent_stopped" or not steps:
        return False
    *earlier, last = steps
    if step_kind(last) != "text_only" or last.get("stop_reason") not in MODEL_STOPS:
        return False
    counted = {"run_command", "malformed"} if attempts else {"run_command"}
    return any(step_kind(step) in counted for step in earlier)


def hit_the_nudge_limit(steps: list[dict], termination_reason: str) -> bool:
    """The run ended because the model stayed text-only through every nudge it was given (D-083, D-084).

    D-083 promised to report how often the limit itself is reached, and `ends_text_only_after_a_command` cannot
    say: it also counts a run that ended on its FIRST text-only turn (limit 1, or a turn the nudge never reached)
    and a run ended by an empty reply, which is structural and never nudged. All of these must hold:
      * `agent_stopped`, and the last step is the model's own text-only turn (`end_turn` or `stop_sequence`);
      * the last step has text: an empty reply cannot be carried into a next request, so it is never nudged and
        says nothing about the limit;
      * the step before it was a nudged one: the limit is reached on a streak, and a streak the loop answered
        with a nudge leaves a `nudged` step directly before the one that ended the run."""
    if termination_reason != "agent_stopped" or len(steps) < 2:
        return False
    *_, previous, last = steps
    return (step_kind(last) == "text_only" and last.get("stop_reason") in MODEL_STOPS
            and bool(last.get("assistant_text")) and not last.get("nudged") and bool(previous.get("nudged")))
