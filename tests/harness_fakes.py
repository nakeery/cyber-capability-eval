"""Fakes for the agent loop: a scripted model, a scripted executor and one shared clock.

The loop takes the model, the executor, the target-health probe, the clock and the step sink as
arguments, so these stand in for Bedrock, Docker and the wall clock. All three advance the SAME
FakeClock, which is what lets a test say "the model took 3 s and the command took 12 s" and then
check that a step's times bound only the 12.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

from agent import run_agent
from execution import ExecResult
from model import ModelReply
from prompt_set import load_prompts

FLAG = "FLAG-AbCdEfGhIjKlMnOpQrStUvWx"
PASSWORD = "pw-AbCdEfGhIjKlMnOpQrStUvWx1234"
RUN_ID = "0123456789abcdef0123456789abcdef"
SECRETS = {"flag": FLAG, "admin_password": PASSWORD}


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 11, 12, 10, 0, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def text_reply(text: str = "I am done.", stop: str = "end_turn", **kwargs) -> ModelReply:
    return ModelReply(content=[{"text": text}] if text else [], stop_reason=stop, input_tokens=100,
                      output_tokens=20, request_id="req", **kwargs)


def call_reply(name: str, arguments: object, *, call_id: str = "tool-1", text: str = "", stop: str = "tool_use",
               **kwargs) -> ModelReply:
    content = ([{"text": text}] if text else []) + [
        {"toolUse": {"toolUseId": call_id, "name": name, "input": arguments}}]
    return ModelReply(content=content, stop_reason=stop, input_tokens=100, output_tokens=20,
                      request_id="req", **kwargs)


def command(cmd: str = "ls", **kwargs) -> ModelReply:
    return call_reply("run_command", {"command": cmd}, **kwargs)


def submit(flag: str = FLAG, **kwargs) -> ModelReply:
    return call_reply("submit_flag", {"flag": flag}, **kwargs)


def outcome(output: str = "ok\n", exit_code: int | None = 0, *, timed_out: bool = False,
            truncated: bool = False, full: str | None = None) -> ExecResult:
    return ExecResult(output_full=output if full is None else full, output_sent=output,
                      truncated=truncated, exit_code=exit_code, timed_out=timed_out)


class FakeModel:
    backend = "bedrock"
    model_id = "fake-model"
    region = "us-east-1"

    def __init__(self, script: list, clock: FakeClock, latency: float = 0.0) -> None:
        self.script, self.clock, self.latency, self.requests = list(script), clock, latency, []

    def converse(self, *, system, messages, tool_config, inference):
        self.requests.append({"system": system, "messages": copy.deepcopy(messages),
                              "tool_config": tool_config, "inference": inference})
        assert self.script, "the loop made a model call the test did not script"
        item = self.script.pop(0)
        self.clock.advance(self.latency)
        if isinstance(item, BaseException):
            raise item
        return item


class FakeExecutor:
    def __init__(self, clock: FakeClock, results: list | None = None, seconds: float = 0.0) -> None:
        self.clock, self.results, self.seconds, self.commands = clock, list(results or []), seconds, []

    def run(self, command: str) -> ExecResult:
        self.commands.append(command)
        self.clock.advance(self.seconds)
        return self.results.pop(0) if self.results else outcome()


def run_loop(script: list, *, results: list | None = None, latency: float = 0.0, exec_seconds: float = 0.0,
             condition: str = "no_hint", health=lambda: True, prompts=None, **overrides):
    """Run the real loop against the fakes. Returns (result, model, executor, recorded steps)."""
    clock = FakeClock()
    model = FakeModel(script, clock, latency)
    executor = FakeExecutor(clock, results, exec_seconds)
    recorded: list[dict] = []
    result = run_agent(model=model, executor=executor, prompts=prompts or load_prompts(), condition=condition,
                       run_id=RUN_ID, secrets=SECRETS, clock=clock, health=health, on_step=recorded.append,
                       **overrides)
    return result, model, executor, recorded
