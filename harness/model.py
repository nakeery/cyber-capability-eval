"""The model-call seam (D-060, D-064): one function in, one reply out.

The agent loop sees only `ModelClient.converse`, so it needs neither boto3 nor Docker, and the
local-model fallback (D-060, phase 5) is one more class with the same method. This module's types
(`ModelReply`, `ModelError`, `ModelClient`) import nothing heavy; boto3 is imported only inside
`bedrock_from_env`, so the loop's tests run without any AWS code loaded.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

ROOT = Path(__file__).resolve().parent.parent

# D-064: five attempts in total (the first call plus four retries). botocore's own `max_attempts`
# counts RETRIES, so five of those would be six calls; `total_max_attempts` is the total.
TOTAL_ATTEMPTS = 5


@dataclass
class ModelReply:
    """One model turn, in the Converse shape whatever the backend (D-060 maps a local runtime onto it)."""

    content: list[dict]          # the assistant's content blocks, as received
    stop_reason: str             # Converse vocabulary
    input_tokens: int
    output_tokens: int
    request_id: str | None       # Bedrock's request id; None for a local backend
    retries: int = 0             # retries this call needed (D-064: attempts - 1)
    raw_stop_reason: str | None = None   # local backends: the value as the server returned it
    raw_completion: str | None = None    # local backends: the text before any tool-call parsing

    @property
    def text(self) -> str:
        return "\n".join(block["text"] for block in self.content if "text" in block)

    @property
    def tool_uses(self) -> list[dict]:
        return [block["toolUse"] for block in self.content if "toolUse" in block]


# What a failed call was, because the three are different things to count (D-065):
#   service           throttling, a server error, expired credentials, a network fault: infrastructure (D-064)
#   model_error       the model's OWN output was unusable and Converse raised instead of returning a stop
#                     reason (observed: a reply cut off by max_tokens in the middle of a tool call)
#   request_rejected  Converse refused what the harness sent: a harness bug, not an API fault
SERVICE, MODEL_ERROR, REQUEST_REJECTED = "service", "model_error", "request_rejected"


class ModelError(Exception):
    """A call failed after its retries (D-064). Carries the retries it used, so `api_retries`
    does not lose the failing call's share, and what kind of failure it was."""

    def __init__(self, message: str, retries: int = 0, kind: str = SERVICE) -> None:
        super().__init__(message)
        self.retries = retries
        self.kind = kind


def classify_error(err: Exception) -> str:
    """Map a botocore exception to a ModelError kind by the error code Converse returned."""
    code = getattr(err, "response", {}).get("Error", {}).get("Code", "")
    if code == "ModelErrorException":
        return MODEL_ERROR
    if code == "ValidationException":
        return REQUEST_REJECTED
    return SERVICE


# Converse's documented temperature range for the Nova models is 0 to 1. The study's sampling (D-084) is
# above it, so a Bedrock call would be refused by the service with a ValidationException; the client says
# so itself, first, in the harness's own words.
BEDROCK_MAX_TEMPERATURE = 1.0


class ModelClient(Protocol):
    backend: str
    model_id: str

    def converse(self, *, system: str, messages: list[dict], tool_config: dict, inference: dict) -> ModelReply:
        """`inference` is the manifest's inference_config: temperature, top_p, max_tokens."""
        ...


@dataclass
class BedrockClient:
    """Bedrock's Converse API through a botocore client built with standard retries (D-064)."""

    client: object
    model_id: str
    region: str
    backend: str = "bedrock"
    _attempts: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        # One `before-send` event fires per HTTP attempt, so attempts - 1 is exact, including
        # for a call that ends in an error (an exception carries no RetryAttempts of its own).
        self.client.meta.events.register("before-send.bedrock-runtime.Converse", self._count_attempt)

    def _count_attempt(self, **_: object) -> None:
        self._attempts += 1

    def converse(self, *, system: str, messages: list[dict], tool_config: dict, inference: dict) -> ModelReply:
        from botocore.exceptions import BotoCoreError, ClientError

        if inference["temperature"] > BEDROCK_MAX_TEMPERATURE:
            # A harness configuration problem, not an API fault: REQUEST_REJECTED, the same kind Converse's
            # own ValidationException gets, so the run ends as harness_error and is investigated (D-065).
            raise ModelError(
                f"temperature {inference['temperature']} is above Bedrock's maximum of {BEDROCK_MAX_TEMPERATURE} "
                "(D-084); no call was made", kind=REQUEST_REJECTED)
        self._attempts = 0
        try:
            response = self.client.converse(
                modelId=self.model_id,
                system=[{"text": system}],
                messages=messages,
                toolConfig={**tool_config, "toolChoice": {"auto": {}}},
                inferenceConfig={
                    "temperature": inference["temperature"],
                    "topP": inference["top_p"],
                    "maxTokens": inference["max_tokens"],
                },
            )
        except (BotoCoreError, ClientError) as err:
            # The class name and AWS's own message only: no request body, so no prompt text.
            raise ModelError(f"{type(err).__name__}: {err}", retries=max(self._attempts - 1, 0),
                             kind=classify_error(err)) from err
        usage = response.get("usage", {})
        return ModelReply(
            content=response["output"]["message"]["content"],
            stop_reason=response["stopReason"],
            input_tokens=usage.get("inputTokens", 0),
            output_tokens=usage.get("outputTokens", 0),
            request_id=response.get("ResponseMetadata", {}).get("RequestId"),
            retries=max(self._attempts - 1, 0),
        )


def make_bedrock_client_config():
    from botocore.config import Config

    return Config(
        retries={"mode": "standard", "total_max_attempts": TOTAL_ATTEMPTS},
        connect_timeout=10,
        read_timeout=120,
    )


def bedrock_from_env(model_key: str = "NOVA_MICRO_MODEL_ID") -> BedrockClient:
    """Build the client the way smoke_test.py does: the project's scoped profile wins over any
    machine-wide AWS_PROFILE, and only the lab IAM user is accepted (D-021, D-022)."""
    import boto3

    sys.path.insert(0, str(ROOT / "harness"))
    from smoke_test import load_env, require_lab_identity

    env = {**load_env(ROOT / ".env.example"), **load_env(ROOT / ".env")}
    profile = env.get("AWS_PROFILE", "model-eval")
    region = env.get("AWS_REGION", "us-east-1")
    lab_user = env.get("LAB_IAM_USER", "model-eval-lab")
    session = boto3.Session(profile_name=profile, region_name=region)
    require_lab_identity(session, lab_user)
    return BedrockClient(
        client=session.client("bedrock-runtime", config=make_bedrock_client_config()),
        model_id=env[model_key],
        region=region,
    )
