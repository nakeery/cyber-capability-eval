"""The prompt assembly (prompts/README.md) and the model-call seam (D-060, D-064).

Part 1 pins how the system text, hint and hash are built from the committed prompts. Part 2 checks
the Converse request and reply, and the retry count, against a fake client and against the real
botocore retry machinery (short-circuited before any HTTP call, so no network is used).
"""

import hashlib
import json
import time
from types import SimpleNamespace

import boto3
import pytest
from botocore.awsrequest import AWSResponse
from botocore.exceptions import ClientError
from model import BedrockClient, ModelError, ModelReply, make_bedrock_client_config
from prompt_set import PROMPTS_DIR, find_leaks, load_prompts

# Made-up values of the production shapes (flag, password, run id); none is a real secret.
FAKE_FLAG = "FLAG-Qm7Lp2Xc9Ts4Vb8Nk1Rw6Yh3"
FAKE_PASSWORD = "Gx4Tq9Lw2Zr7Hn5Bp8Mc3Kd6Je1"
FAKE_RUN_ID = "3f9a1c07b2d84e6fa51c0d9e72b4a68f"

EVENT = "before-send.bedrock-runtime.Converse"
CANNED_SUCCESS = {
    "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
    "stopReason": "end_turn",
    "usage": {"inputTokens": 7, "outputTokens": 3},
    "ResponseMetadata": {"RequestId": "req-1"},
}
INFERENCE = {"temperature": 0.7, "top_p": 0.9, "max_tokens": 1024}
TOOLS = [{"toolSpec": {"name": "t", "inputSchema": {"json": {"type": "object", "properties": {}}}}}]
MESSAGES = [{"role": "user", "content": [{"text": "go"}]}]


def read_prompt(name):
    return (PROMPTS_DIR / name).read_bytes().decode("utf-8")


# --- Part 1: prompt_set ------------------------------------------------------

def test_system_text_no_hint_is_the_template_with_the_url_filled_in():
    expected = read_prompt("system.md").replace("{TARGET_URL}", "http://target:8080")
    assert load_prompts().system_text("no_hint") == expected


def test_system_text_hint_appends_one_newline_and_the_hint():
    prompts = load_prompts()
    assert prompts.system_text("hint") == prompts.system_text("no_hint") + "\n" + read_prompt("hint.txt")


def test_system_prompt_hash_is_sha256_of_the_system_text():
    prompts = load_prompts()
    for condition in ("no_hint", "hint"):
        digest = hashlib.sha256(prompts.system_text(condition).encode("utf-8")).hexdigest()
        assert prompts.system_prompt_hash(condition) == "sha256:" + digest


def test_system_prompt_hash_differs_by_condition():
    prompts = load_prompts()
    assert prompts.system_prompt_hash("hint") != prompts.system_prompt_hash("no_hint")


def test_hint_text_is_the_hint_file_only_in_the_hint_condition():
    prompts = load_prompts()
    assert prompts.hint_text("hint") == read_prompt("hint.txt")
    assert prompts.hint_text("no_hint") is None


@pytest.mark.parametrize("method", ["system_text", "hint_text", "system_prompt_hash"])
def test_unknown_condition_is_rejected(method):
    with pytest.raises(ValueError):
        getattr(load_prompts(), method)("bogus")


def test_harness_authored_texts_cover_every_fixed_text_in_hint_condition():
    prompts = load_prompts()
    texts = prompts.harness_authored_texts("hint")
    messages = json.loads(read_prompt("messages.json"))
    expected = [
        prompts.system_text("hint"),
        read_prompt("opening.txt"),
        messages["submit_flag_reply"],
        messages["truncation_marker"],
        messages["timeout_notice"],
        messages["empty_output_notice"],
        messages["continue_nudge"],
        *messages["errors"].values(),
        json.dumps(json.loads(read_prompt("tools.json")), sort_keys=True),
    ]
    for text in expected:
        assert text in texts


def test_find_leaks_returns_empty_when_no_secret_appears():
    assert find_leaks(["nothing to see here"], {"flag": FAKE_FLAG}) == []


def test_find_leaks_returns_sorted_names_not_values():
    texts = [f"first {FAKE_FLAG} then {FAKE_PASSWORD}"]
    assert find_leaks(texts, {"flag": FAKE_FLAG, "admin_password": FAKE_PASSWORD}) == ["admin_password", "flag"]


def test_find_leaks_ignores_an_empty_secret():
    assert find_leaks(["anything at all"], {"flag": ""}) == []


@pytest.mark.parametrize("condition", ["no_hint", "hint"])
def test_committed_prompts_hold_no_secret_shaped_token(condition):
    secrets = {"flag": FAKE_FLAG, "admin_password": FAKE_PASSWORD, "run_id": FAKE_RUN_ID}
    texts = load_prompts().harness_authored_texts(condition)
    assert find_leaks(texts, secrets) == []


# --- Part 2: model.py --------------------------------------------------------

def test_reply_text_joins_text_blocks_and_ignores_tool_use():
    reply = ModelReply(
        content=[{"text": "a"}, {"toolUse": {"name": "t", "input": {}}}, {"text": "b"}],
        stop_reason="tool_use", input_tokens=1, output_tokens=1, request_id=None,
    )
    assert reply.text == "a\nb"


def test_reply_tool_uses_returns_inner_dicts_in_order():
    first, second = {"name": "run_command", "input": {"command": "ls"}}, {"name": "submit_flag", "input": {"flag": "x"}}
    reply = ModelReply(
        content=[{"toolUse": first}, {"text": "between"}, {"toolUse": second}],
        stop_reason="tool_use", input_tokens=1, output_tokens=1, request_id=None,
    )
    assert reply.tool_uses == [first, second]


class FakeEvents:
    def __init__(self):
        self.registered = []

    def register(self, event_name, handler):
        self.registered.append((event_name, handler))


class FakeBedrock:
    """Stands in for a boto3 client: records the converse kwargs and fires the registered
    before-send handlers `attempts` times, so the counter sees the attempts it would see live."""

    def __init__(self, attempts=1, error=None):
        self.meta = SimpleNamespace(events=FakeEvents())
        self.attempts = attempts
        self.error = error
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        for _ in range(self.attempts):
            for name, handler in self.meta.events.registered:
                if name == EVENT:
                    handler(request=None)
        if self.error is not None:
            raise self.error
        return CANNED_SUCCESS


def test_bedrock_client_registers_an_attempt_counter():
    fake = FakeBedrock()
    BedrockClient(client=fake, model_id="m", region="us-east-1")
    assert [name for name, _ in fake.meta.events.registered] == [EVENT]


def test_converse_builds_the_request_and_returns_the_reply():
    fake = FakeBedrock()
    client = BedrockClient(client=fake, model_id="model-x", region="us-east-1")
    tool_config = {"tools": TOOLS}
    messages = [{"role": "user", "content": [{"text": "go"}]}]

    reply = client.converse(system="S", messages=messages, tool_config=tool_config, inference=INFERENCE)

    call = fake.calls[0]
    assert call["modelId"] == "model-x"
    assert call["system"] == [{"text": "S"}]
    assert call["messages"] == messages
    assert call["toolConfig"] == {"tools": TOOLS, "toolChoice": {"auto": {}}}
    assert call["inferenceConfig"] == {"temperature": 0.7, "topP": 0.9, "maxTokens": 1024}
    assert tool_config == {"tools": TOOLS}
    assert reply.content == [{"text": "hi"}]
    assert reply.stop_reason == "end_turn"
    assert (reply.input_tokens, reply.output_tokens) == (7, 3)
    assert reply.request_id == "req-1"
    assert reply.retries == 0


def test_converse_wraps_a_client_error_with_its_retry_count():
    error = ClientError({"Error": {"Code": "ThrottlingException", "Message": "slow down"}}, "Converse")
    fake = FakeBedrock(attempts=3, error=error)
    client = BedrockClient(client=fake, model_id="m", region="us-east-1")

    with pytest.raises(ModelError) as info:
        client.converse(system="S", messages=MESSAGES, tool_config={"tools": TOOLS}, inference=INFERENCE)

    assert info.value.retries == 2
    assert "ThrottlingException" in str(info.value)


class RawBody:
    def __init__(self, body):
        self._body = body

    def stream(self):
        yield self._body

    def read(self):
        return self._body


class ScriptedHttp:
    """A before-send handler that answers each HTTP attempt from a script of status codes, so
    botocore's real retry logic runs without any network call. 200 gets a Converse body."""

    def __init__(self, statuses):
        self.statuses = list(statuses)
        self.consumed = 0

    def __call__(self, **_):
        status = self.statuses.pop(0)
        self.consumed += 1
        body = CANNED_BODY if status == 200 else {"message": "unavailable"}
        return AWSResponse(
            "https://bedrock-runtime.us-east-1.amazonaws.com/model/model-x/converse",
            status,
            {"content-type": "application/json", "x-amzn-requestid": "req-1"},
            RawBody(json.dumps(body).encode("utf-8")),
        )


CANNED_BODY = {k: v for k, v in CANNED_SUCCESS.items() if k != "ResponseMetadata"}


def real_client(statuses):
    client = boto3.client(
        "bedrock-runtime", region_name="us-east-1",
        aws_access_key_id="x", aws_secret_access_key="x",
        config=make_bedrock_client_config(),
    )
    bedrock = BedrockClient(client=client, model_id="model-x", region="us-east-1")
    http = ScriptedHttp(statuses)
    client.meta.events.register(EVENT, http)
    return bedrock, http


def converse_once(bedrock):
    return bedrock.converse(system="S", messages=MESSAGES, tool_config={"tools": TOOLS}, inference=INFERENCE)


@pytest.fixture
def no_sleep(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda seconds: None)


def test_retry_config_is_standard_with_five_total_attempts():
    config = make_bedrock_client_config()
    assert config.retries == {"mode": "standard", "total_max_attempts": 5}
    assert config.read_timeout == 120


def test_real_client_retries_twice_then_succeeds(no_sleep):
    bedrock, http = real_client([503, 503, 200])
    reply = converse_once(bedrock)
    assert reply.retries == 2
    assert reply.text == "hi"
    assert http.consumed == 3


def test_real_client_gives_up_after_five_attempts(no_sleep):
    bedrock, http = real_client([503] * 6)
    with pytest.raises(ModelError) as info:
        converse_once(bedrock)
    assert info.value.retries == 4
    assert http.consumed == 5


def test_real_client_first_attempt_success_has_no_retries(no_sleep):
    bedrock, http = real_client([200])
    assert converse_once(bedrock).retries == 0
    assert http.consumed == 1


# --- what kind of failure a failed call was (D-065) -------------------------------------

@pytest.mark.parametrize("code,kind", [
    ("ModelErrorException", "model_error"),        # the model's own output was unusable (observed with a cut-off tool call)
    ("ValidationException", "request_rejected"),   # Converse refused what the harness sent: a harness bug
    ("ThrottlingException", "service"),
    ("ServiceUnavailableException", "service"),
    ("ExpiredTokenException", "service"),
    ("AccessDeniedException", "service"),
    ("SomethingNobodyHasSeen", "service"),
])
def test_a_failed_call_is_tagged_with_its_kind(code, kind):
    from botocore.exceptions import ClientError
    from model import BedrockClient, ModelError

    class Failing:
        class meta:
            class events:
                register = staticmethod(lambda *a, **k: None)

        def converse(self, **kwargs):
            raise ClientError({"Error": {"Code": code, "Message": "x"}}, "Converse")

    client = BedrockClient(client=Failing(), model_id="m", region="us-east-1")
    with pytest.raises(ModelError) as err:
        client.converse(system="s", messages=[], tool_config={"tools": []}, inference={"temperature": 0.7, "top_p": 0.9, "max_tokens": 1})
    assert err.value.kind == kind


def test_bedrock_refuses_a_temperature_above_its_range_before_calling_the_service():
    from model import BEDROCK_MAX_TEMPERATURE, BedrockClient, ModelError

    class NeverCalled:
        class meta:
            class events:
                register = staticmethod(lambda *a, **k: None)

        def converse(self, **kwargs):
            raise AssertionError("a request that cannot be valid must not reach the service")

    client = BedrockClient(client=NeverCalled(), model_id="m", region="us-east-1")
    hot = {"temperature": BEDROCK_MAX_TEMPERATURE + 0.2, "top_p": 0.9, "max_tokens": 1024}
    with pytest.raises(ModelError) as err:
        client.converse(system="s", messages=[], tool_config={"tools": []}, inference=hot)
    # The harness's own configuration problem: the kind Converse's ValidationException gets, never an outage.
    assert (err.value.kind, err.value.retries) == ("request_rejected", 0)
    assert "D-084" in str(err.value)


def test_a_network_fault_is_a_service_failure():
    from botocore.exceptions import EndpointConnectionError
    from model import classify_error
    assert classify_error(EndpointConnectionError(endpoint_url="https://example.invalid")) == "service"
