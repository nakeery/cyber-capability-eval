"""step_kind reads a recorded step back to the turn the loop classified (D-072 R3, D-075).

The first test is the one that matters: every stop reason against every content shape goes through the REAL loop,
and the step it records must name the same turn `classify_turn` named. If the loop's rules change and this
module does not, or the other way round, that test fails.
"""

import pytest
from agent import Limits, classify_turn
from harness_fakes import command, run_loop, text_reply
from model import ModelReply
from step_kind import ends_text_only_after_a_command, hit_the_nudge_limit, models_own_words, step_kind

STOPS = ["tool_use", "end_turn", "max_tokens", "stop_sequence", "guardrail_intervened", "content_filtered",
         "malformed_model_output", "malformed_tool_use", "model_context_window_exceeded", "some_future_reason"]
SHAPES = {
    "text": [{"text": "hello"}],
    "one_call": [{"toolUse": {"toolUseId": "a", "name": "run_command", "input": {"command": "ls"}}}],
    "submit": [{"toolUse": {"toolUseId": "a", "name": "submit_flag", "input": {"flag": "x"}}}],
    "two_calls": [{"toolUse": {"toolUseId": "a", "name": "run_command", "input": {"command": "ls"}}},
                  {"toolUse": {"toolUseId": "b", "name": "run_command", "input": {"command": "ls"}}}],
    "bad_call": [{"toolUse": {"toolUseId": "a", "name": "run_command", "input": {"cmd": "ls"}}}],
    "unknown_tool": [{"toolUse": {"toolUseId": "a", "name": "bash", "input": {"command": "ls"}}}],
    "nul_command": [{"toolUse": {"toolUseId": "a", "name": "run_command", "input": {"command": "ls\x00rm"}}}],
    "text_and_call": [{"text": "I will list the files."},
                      {"toolUse": {"toolUseId": "a", "name": "run_command", "input": {"command": "ls"}}}],
    "empty": [],
}


@pytest.mark.parametrize("stop", STOPS)
@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_the_step_record_names_the_turn_the_loop_classified(stop, shape):
    reply = ModelReply(content=SHAPES[shape], stop_reason=stop, input_tokens=1, output_tokens=1, request_id="r")
    _, _, _, steps = run_loop([reply], limits=Limits(step_cap=1))       # one step, so no second model call is needed
    assert step_kind(steps[0]) == classify_turn(reply).kind


def test_a_full_window_is_an_empty_step_that_only_its_stop_reason_tells_from_a_text_only_turn():
    # The reason the helper exists: apart from `stop_reason`, the two records are the same.
    _, _, _, window = run_loop([text_reply("", stop="model_context_window_exceeded")])
    _, _, _, text = run_loop([text_reply("", stop="end_turn")])
    for step in (window[0], text[0]):
        assert step["tool_name"] is None and "tool_call_error" not in step and step["assistant_text"] == ""
    assert (step_kind(window[0]), step_kind(text[0])) == ("window_exceeded", "text_only")
    assert not models_own_words(window[0]) and models_own_words(text[0])


@pytest.mark.parametrize("stop", ["content_filtered", "guardrail_intervened"])
def test_a_platform_block_keeps_the_platforms_words_in_assistant_text_and_is_not_the_models(stop):
    message = "The generated text has been blocked by our content filters."
    _, _, _, steps = run_loop([text_reply(message, stop=stop)])
    assert steps[0]["assistant_text"] == message                       # recorded as if the model had written it
    assert step_kind(steps[0]) == "provider_block" and not models_own_words(steps[0])


@pytest.mark.parametrize("stop", ["end_turn", "stop_sequence"])
def test_a_real_text_only_turn_is_the_models_own_words(stop):
    _, _, _, steps = run_loop([text_reply("I cannot continue.", stop=stop)])
    assert step_kind(steps[0]) == "text_only" and models_own_words(steps[0])


def test_a_malformed_call_and_a_command_and_a_submit_are_named_for_what_they_are():
    _, _, _, steps = run_loop([ModelReply(content=SHAPES["bad_call"], stop_reason="tool_use", input_tokens=1,
                                          output_tokens=1, request_id="r"), command("ls"),
                               ModelReply(content=SHAPES["submit"], stop_reason="tool_use", input_tokens=1,
                                          output_tokens=1, request_id="r")])
    assert [step_kind(s) for s in steps] == ["malformed", "run_command", "submit_flag"]


# --- the count D-067's spike warned about, as D-075 defines it -------------------------------------
# The run ENDED (`agent_stopped`) on a text-only turn the MODEL ended (end_turn or stop_sequence), after a command.

BAD = ModelReply(content=SHAPES["bad_call"], stop_reason="tool_use", input_tokens=1, output_tokens=1, request_id="r")


def counted(script, *, attempts=False, **kwargs):
    result, _, _, steps = run_loop(script, **kwargs)
    return ends_text_only_after_a_command(steps, result.termination_reason, attempts=attempts)


def test_a_text_only_ending_after_a_command_is_counted():
    assert counted([command("ls"), text_reply("It looks empty, so I am done.")])


def test_a_text_only_turn_that_stops_on_stop_sequence_is_counted_too():
    assert counted([command("ls"), text_reply("Done.", stop="stop_sequence")])


def test_a_text_only_first_turn_is_not_counted():
    assert not counted([text_reply("I will not do this.")])
    assert not counted([text_reply("I will not do this.")], attempts=True)


@pytest.mark.parametrize("stop", ["model_context_window_exceeded", "content_filtered", "guardrail_intervened"])
def test_a_run_that_ended_on_a_full_window_or_a_platform_block_is_not_a_text_only_ending(stop):
    # The false count D-072 R3 exists to prevent: the last step is empty or the platform's, not the model's.
    assert not counted([command("ls"), text_reply("", stop=stop)])


def test_a_run_that_ended_on_a_command_is_not_counted():
    assert not counted([command("ls"), command("pwd"), command("id")], limits=Limits(step_cap=3))


def test_a_text_only_turn_on_the_last_step_the_cap_allows_is_not_counted():
    # The run ended as step_cap: the turn cost nothing, whatever the cap would have allowed next.
    result, _, _, steps = run_loop([command("ls"), text_reply("Done.")], limits=Limits(step_cap=2))
    assert result.termination_reason == "step_cap" and step_kind(steps[-1]) == "text_only"
    assert not ends_text_only_after_a_command(steps, result.termination_reason)


def test_a_text_only_turn_that_fills_the_window_by_the_estimate_is_not_counted():
    # The other route to context_limit: an ORDINARY text-only turn after which the harness judges the window full.
    big = ModelReply(content=[{"text": "Done."}], stop_reason="end_turn", input_tokens=25_000, output_tokens=20,
                     request_id="r")
    result, _, _, steps = run_loop([command("ls"), big], limits=Limits(context_ceiling=20_000))
    assert result.termination_reason == "context_limit" and step_kind(steps[-1]) == "text_only"
    assert not ends_text_only_after_a_command(steps, result.termination_reason)


def test_an_empty_reply_the_model_ended_is_counted_but_one_with_another_stop_reason_is_not():
    # The loop calls ANY empty reply text-only. An empty end_turn is the model stopping; an empty reply with a
    # server stop type the harness does not recognise (malformed_model_output) is not the model's decision.
    empty = lambda stop: ModelReply(content=[], stop_reason=stop, input_tokens=1, output_tokens=0, request_id="r")
    assert counted([command("ls"), empty("end_turn")])
    for stop in ("malformed_model_output", "max_tokens", "some_future_reason"):
        result, _, _, steps = run_loop([command("ls"), empty(stop)])
        assert step_kind(steps[-1]) == "text_only" and result.termination_reason == "agent_stopped"
        assert not ends_text_only_after_a_command(steps, result.termination_reason), stop


def test_the_termination_reason_is_required_to_be_agent_stopped():
    _, _, _, steps = run_loop([command("ls"), text_reply("Done.")])
    assert ends_text_only_after_a_command(steps, "agent_stopped")
    for reason in ("step_cap", "context_limit", "harness_error", "api_error", "target_down", "submitted"):
        assert not ends_text_only_after_a_command(steps, reason), reason


# the secondary count: a malformed tool-call attempt is also a tool call, and returns the harness's error text

def test_a_text_only_ending_after_a_malformed_attempt_and_no_command_is_only_the_secondary_count():
    assert not counted([BAD, text_reply("I give up.")])
    assert counted([BAD, text_reply("I give up.")], attempts=True)


def test_a_command_is_counted_by_both_counts():
    assert counted([command("ls"), text_reply("Done.")], attempts=True)


def test_no_steps_is_not_counted():
    assert not ends_text_only_after_a_command([], "agent_stopped")
    assert not ends_text_only_after_a_command([], "agent_stopped", attempts=True)


# --- hit_the_nudge_limit (D-083, D-084) ------------------------------------------------

def test_a_run_that_stayed_text_only_through_every_nudge_hit_the_limit():
    result, _, _, steps = run_loop([command("ls"), text_reply("a"), text_reply("b"), text_reply("c")],
                                   limits=Limits(text_only_limit=3))
    assert result.termination_reason == "agent_stopped"
    assert hit_the_nudge_limit(steps, result.termination_reason)
    assert ends_text_only_after_a_command(steps, result.termination_reason)       # the wider count includes it


def test_ending_on_the_first_text_only_turn_is_not_the_nudge_limit():
    # limit 1 is D-063's old rule: nothing was ever nudged, so no limit was "reached".
    result, _, _, steps = run_loop([command("ls"), text_reply("Done.")])
    assert ends_text_only_after_a_command(steps, result.termination_reason)
    assert not hit_the_nudge_limit(steps, result.termination_reason)


def test_an_empty_reply_after_a_nudge_is_structural_and_not_the_limit():
    result, _, _, steps = run_loop([command("ls"), text_reply("a"), text_reply("", stop="end_turn")],
                                   limits=Limits(text_only_limit=4))
    assert result.termination_reason == "agent_stopped" and steps[-2]["nudged"] is True
    assert not hit_the_nudge_limit(steps, result.termination_reason)


def test_a_platform_block_after_a_nudge_and_other_terminations_are_not_the_limit():
    result, _, _, steps = run_loop([command("ls"), text_reply("a"), text_reply("", stop="content_filtered")],
                                   limits=Limits(text_only_limit=4))
    assert not hit_the_nudge_limit(steps, result.termination_reason)
    assert not hit_the_nudge_limit(steps, "step_cap") and not hit_the_nudge_limit([], "agent_stopped")
