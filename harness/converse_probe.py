"""Check how Bedrock's Converse API treats the conversation shapes the harness produces (D-063, D-065).

D-063 says "Converse expects a result for every tool call id; the phase 4 harness test confirms this
against the real API". Several other shapes the loop relies on were assumed, not known. This sends a
handful of small SYNTHETIC conversations (no lab, no target, no attack content) and prints whether each
was accepted, so the loop's choices rest on observation:

    .venv/Scripts/python harness/converse_probe.py

Each case is one real call to the evaluated model (a few hundred tokens). Run it again after a model or SDK
change; a case that starts failing there means the loop would fail the same way mid-run.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "harness"))

from model import ModelError, bedrock_from_env  # noqa: E402
from prompt_set import load_prompts  # noqa: E402

PROMPTS = load_prompts()
INFERENCE = {"temperature": 0.0, "top_p": 0.9, "max_tokens": 1024}   # the production limit (D-062)
SYSTEM = "You are operating a Linux shell through the run_command tool."


def call(tool_name: str, call_id: str, arguments: dict) -> dict:
    return {"toolUse": {"toolUseId": call_id, "name": tool_name, "input": arguments}}


def result(call_id: str, *content: dict) -> dict:
    return {"toolResult": {"toolUseId": call_id, "content": list(content)}}


OPENING = {"role": "user", "content": [{"text": PROMPTS.opening}]}

CASES = {
    "a result with text (baseline)": [
        OPENING,
        {"role": "assistant", "content": [call("run_command", "t1", {"command": "ls"})]},
        {"role": "user", "content": [result("t1", {"text": "notes.txt"})]},
    ],
    "a result with EMPTY text": [
        OPENING,
        {"role": "assistant", "content": [call("run_command", "t1", {"command": "true"})]},
        {"role": "user", "content": [result("t1", {"text": ""})]},
    ],
    "a result with an EMPTY content list": [
        OPENING,
        {"role": "assistant", "content": [call("run_command", "t1", {"command": "true"})]},
        {"role": "user", "content": [result("t1")]},
    ],
    "the committed empty-output notice": [
        OPENING,
        {"role": "assistant", "content": [call("run_command", "t1", {"command": "true"})]},
        {"role": "user", "content": [result("t1", {"text": PROMPTS.empty_output_notice})]},
    ],
    "history that calls a tool NOT in toolConfig (unknown_tool)": [
        OPENING,
        {"role": "assistant", "content": [call("bash", "t1", {"command": "ls"})]},
        {"role": "user", "content": [result("t1", {"text": PROMPTS.error_text("unknown_tool")})]},
    ],
    "two calls in one turn, one result each (multiple_calls)": [
        OPENING,
        {"role": "assistant", "content": [call("run_command", "t1", {"command": "ls"}),
                                          call("run_command", "t2", {"command": "pwd"})]},
        {"role": "user", "content": [result("t1", {"text": PROMPTS.error_text("multiple_calls")}),
                                     result("t2", {"text": PROMPTS.error_text("multiple_calls")})]},
    ],
    "a call with the wrong arguments (invalid_arguments)": [
        OPENING,
        {"role": "assistant", "content": [call("run_command", "t1", {"cmd": "ls"})]},
        {"role": "user", "content": [result("t1", {"text": PROMPTS.error_text("invalid_arguments")})]},
    ],
    "text-only assistant turn, then a plain user error text (unusable_output)": [
        OPENING,
        {"role": "assistant", "content": [{"text": "I was about to run a command but"}]},
        {"role": "user", "content": [{"text": PROMPTS.error_text("unusable_output")}]},
    ],
}


def main() -> int:
    model = bedrock_from_env()
    print(f"model {model.model_id}\n")
    failures = 0
    for name, messages in CASES.items():
        try:
            reply = model.converse(system=SYSTEM, messages=messages, tool_config=PROMPTS.tool_config, inference=INFERENCE)
            print(f"ACCEPTED  {name}  (stop: {reply.stop_reason})")
        except ModelError as err:
            failures += 1
            print(f"REJECTED  {name}\n          {str(err)[:240]}")
    print(f"\n{len(CASES) - failures} accepted, {failures} rejected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
