"""Phase 0 smoke test: can each Nova model make a tool call through Converse?

The whole harness depends on client-side tool calling, and the Nova Pro model
card omits it from its feature list (DECISIONS.md, review round 1). So phase 0
is "done" only when BOTH models return a real toolUse block, not just text.

Usage (from the repository root):
    .venv/Scripts/python harness/smoke_test.py
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import boto3

REPO_ROOT = Path(__file__).resolve().parent.parent

# The same tool shape the real harness will use (phase 4). Nova requires the
# input schema to be a top-level object with only type/properties/required.
RUN_COMMAND_TOOL = {
    "toolSpec": {
        "name": "run_command",
        "description": "Run a shell command in the lab container and return its output.",
        "inputSchema": {
            "json": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to run.",
                    }
                },
                "required": ["command"],
            }
        },
    }
}

SYSTEM_PROMPT = "You are operating a Linux shell through the run_command tool."
USER_PROMPT = "List the files in the current directory."

# D-011: sampling settings the experiment will use.
INFERENCE_CONFIG = {"temperature": 0.7, "topP": 0.9, "maxTokens": 512}


def load_env(path: Path) -> dict[str, str]:
    """Minimal .env reader (no extra dependency). Ignores blanks and comments."""
    env: dict[str, str] = {}
    if not path.exists():
        return env
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip()
    return env


def require_lab_identity(session: boto3.Session, lab_user: str) -> None:
    """Abort unless the active credentials are exactly the scoped lab user (D-022).

    An allow-list, not a block-list: refusing only root would still let an admin
    IAM user through. sts:GetCallerIdentity needs no IAM permissions, so this
    works for the scoped user. The ARN is never printed (it holds the account ID).
    """
    arn = session.client("sts").get_caller_identity()["Arn"]
    if not arn.endswith(f":user/{lab_user}"):
        kind = "root" if arn.endswith(":root") else arn.split(":")[-1].split("/")[0]
        sys.exit(
            f"Refusing to run: the active identity type is '{kind}', and only "
            f"user/{lab_user} is allowed. See infra/bootstrap/README.md"
        )


def extract_tool_use(response: dict) -> dict:
    """Return the toolUse block from a Converse response, or raise ValueError.

    Converse response shape (abridged):
        {
          "stopReason": "tool_use" | "end_turn" | "max_tokens" | ...,
          "output": {"message": {"role": "assistant",
                                 "content": [{"text": "..."},
                                             {"toolUse": {"toolUseId": "...",
                                                          "name": "run_command",
                                                          "input": {"command": "ls"}}}]}},
          "usage": {"inputTokens": 123, "outputTokens": 45, ...}
        }
    """
    content = response.get("output", {}).get("message", {}).get("content", [])
    tool_uses = [block["toolUse"] for block in content if "toolUse" in block]

    if not tool_uses:
        # Show what the model said instead, so a failure is diagnosable.
        text = " ".join(block.get("text", "") for block in content).strip()
        raise ValueError(
            f"no toolUse block (stopReason={response.get('stopReason')!r}); "
            f"model replied with text: {text[:200]!r}"
        )
    if response.get("stopReason") != "tool_use":
        raise ValueError(f"toolUse present but stopReason={response.get('stopReason')!r}")

    tool_use = tool_uses[0]
    if tool_use.get("name") != "run_command":
        raise ValueError(f"called unknown tool {tool_use.get('name')!r}")
    command = tool_use.get("input", {}).get("command")
    if not isinstance(command, str) or not command.strip():
        raise ValueError(f"run_command input has no usable 'command': {tool_use.get('input')!r}")
    if not tool_use.get("toolUseId"):
        raise ValueError("toolUse block has no toolUseId (needed to send the result back)")
    return tool_use


def check_model(client, model_id: str) -> bool:
    started = time.perf_counter()
    response = client.converse(
        modelId=model_id,
        system=[{"text": SYSTEM_PROMPT}],
        messages=[{"role": "user", "content": [{"text": USER_PROMPT}]}],
        toolConfig={"tools": [RUN_COMMAND_TOOL], "toolChoice": {"auto": {}}},
        inferenceConfig=INFERENCE_CONFIG,
    )
    elapsed = time.perf_counter() - started
    usage = response.get("usage", {})

    print(f"\n== {model_id}")
    print(f"   stopReason: {response.get('stopReason')}   "
          f"tokens in/out: {usage.get('inputTokens')}/{usage.get('outputTokens')}   "
          f"latency: {elapsed:.1f}s")
    try:
        tool_use = extract_tool_use(response)
    except ValueError as err:
        print(f"   FAIL: {err}")
        return False
    print(f"   PASS: {tool_use['name']}({tool_use['input']})")
    return True


def main() -> int:
    env = {**load_env(REPO_ROOT / ".env.example"), **load_env(REPO_ROOT / ".env")}
    # The project's profile wins over any machine-wide AWS_PROFILE (D-022):
    # a global variable set for admin work must not silently change who we run as.
    profile = env.get("AWS_PROFILE", "model-eval")
    if os.environ.get("AWS_PROFILE", profile) != profile:
        print(f"note: ignoring AWS_PROFILE from the environment; using '{profile}'")
    region = env.get("AWS_REGION", "us-east-1")
    lab_user = env.get("LAB_IAM_USER", "model-eval-lab")
    model_ids = [env["NOVA_MICRO_MODEL_ID"], env["NOVA_PRO_MODEL_ID"]]

    session = boto3.Session(profile_name=profile, region_name=region)
    require_lab_identity(session, lab_user)
    client = session.client("bedrock-runtime")

    print(f"profile={profile} region={region} boto3={boto3.__version__}")
    results = [check_model(client, model_id) for model_id in model_ids]
    print("\nALL PASS" if all(results) else "\nSOME CHECKS FAILED")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
