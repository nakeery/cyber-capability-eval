"""The local-model client against a stub llama-server (D-060, D-067).

No model and no llama-server: a stub on 127.0.0.1 (port 0, in a thread) answers the three endpoints the client
uses, in the shapes observed from build b12478. Each test states one rule; the end-to-end tests run the real
agent loop on top of the client.
"""

import copy
import hashlib
import itertools
import json
import threading
from collections import deque
from dataclasses import asdict, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import telemetry
from agent import run_agent
import local_model  # noqa: E402
from harness_fakes import RUN_ID, SECRETS, FakeClock, FakeExecutor, outcome
from local_model import (NEUTRAL_SAMPLER, ZERO_HASH, LocalClient, LocalPin, ServerCheckError, parse_completion,
                         sha256_text, to_openai_messages, to_openai_tools, verify_weights)
from model import REQUEST_REJECTED, SERVICE, ModelError
from prompt_set import load_prompts

API_KEY = "test-key"
TEMPLATE = "stub chat template v1"
SYSTEM = "You are a stub."
OPENING = "Begin."
INFERENCE = {"temperature": 0.7, "top_p": 0.9, "max_tokens": 512}
TOOLS = load_prompts().tool_config
TOOL_CALL_RUN = '<tool_call>\n{"name": "run_command", "arguments": {"command": "ls"}}\n</tool_call>'
UNCLOSED_CALL = '<tool_call>\n{"name": "run_command", "arguments": {"command": "ls"}}'
DEFAULT_COMPLETION = {"content": "hello there", "stop_type": "eos", "stopping_word": "", "truncated": False,
                      "tokens_evaluated": 282, "tokens_predicted": 22}


def error_body(code, type_, message="rejected", **extra):
    return {"error": {"code": code, "message": message, "type": type_, **extra}}


def completion(content, stop_type="eos", **extra):
    return {**DEFAULT_COMPLETION, "content": content, "stop_type": stop_type, **extra}


def id_counter():
    counter = itertools.count(1)
    return lambda: f"id{next(counter)}"


def call_text(body):
    return "<tool_call>\n" + json.dumps(body) + "\n</tool_call>"


# --- the stub -----------------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def _handle(self, method):
        stub = self.server.stub
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        record = {"method": method, "path": self.path,
                  "headers": {k.lower(): v for k, v in self.headers.items()},
                  "body": json.loads(raw) if raw else None}
        stub.requests.append(record)
        if self.headers.get("Authorization") != f"Bearer {API_KEY}":
            status, payload = 401, error_body(401, "authentication_error", "Invalid API Key")
        else:
            status, payload = stub.answer(method, self.path, record["body"])
        record["response"] = payload
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class StubServer:
    """Every request is recorded (headers, parsed body, the answer). /completion answers from `completions`
    (a queue of (status, payload) pairs) and falls back to a plain reply. /apply-template renders each
    message as ChatML and puts the tools in a system block at the front, so the prefix hash covers them."""

    def __init__(self):
        self.requests: list[dict] = []
        self.completions: deque = deque()
        self.props = {"build_info": "b12478-8d1599fca", "model_path": "C:\\models\\Qwen3-8B-Q4_K_M.gguf",
                      "chat_template": TEMPLATE, "total_slots": 1, "default_generation_settings": {"n_ctx": 16384}}
        self.system_before_user = False
        self.render_without_prompt = False
        self.tools_marker = "<tools>"  # how the stub's template opens its tools block (a changed template or flag changes this)
        self.shift_on = False          # simulate a server started WITHOUT --no-context-shift
        self.overflow_status = 400     # what the server answers to a prompt over its window
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.stub = self
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self._closed = False
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        if not self._closed:
            self._closed = True
            self.server.shutdown()
            self.server.server_close()

    def answer(self, method, path, body):
        if (method, path) == ("GET", "/props"):
            return 200, self.props
        if (method, path) == ("POST", "/apply-template"):
            return 200, ({} if self.render_without_prompt else {"prompt": self.render(body)})
        if (method, path) == ("POST", "/completion"):
            if len(body.get("prompt", "")) > 40_000 and not self.shift_on:       # far over any window the tests use
                return self.overflow_status, error_body(self.overflow_status, "exceed_context_size_error", "over the window",
                                                       n_prompt_tokens=60_000, n_ctx=16384)
            return self.completions.popleft() if self.completions else (200, dict(DEFAULT_COMPLETION))
        return 404, error_body(404, "not_found_error", "no such endpoint")

    def render(self, body):
        parts = []
        if self.system_before_user:
            parts.append("<|im_start|>system\nYou are a stub.<|im_end|>\n")
        if body.get("tools"):
            parts.append("<|im_start|>system\n" + self.tools_marker + json.dumps(body["tools"], sort_keys=True) + "</tools><|im_end|>\n")
        for message in body["messages"]:
            parts.append(f"<|im_start|>{message['role']}\n{message.get('content') or ''}<|im_end|>\n")
        parts.append("<|im_start|>assistant\n")
        return "".join(parts)

    def paths(self):
        return [r["path"] for r in self.requests]


_REAL_INSPECTOR = local_model.inspect_server_process      # the fixture below replaces the module's; these tests need the real one


@pytest.fixture(autouse=True)
def a_matching_server_process(monkeypatch):
    """prepare() asks the operating system about the server's process. There is no real llama-server here, so a fake one
    is installed for every test in this file: loopback, the pinned weights file, and the flags of an EMPTY pin (the tests'
    own `pin` fixture has none). Tests of the process check itself pass their own facts to check_process directly."""
    monkeypatch.setattr(local_model, "inspect_server_process", lambda port: {
        "pid": 4242, "path": "C:\\runtime\\llama-server.exe", "address": "127.0.0.1",
        "command_line": '"C:\\runtime\\llama-server.exe" -m C:\\models\\Qwen3-8B-Q4_K_M.gguf'})


@pytest.fixture
def stub():
    server = StubServer()
    yield server
    server.close()


@pytest.fixture
def pin():
    return LocalPin(model_id="Qwen/Qwen3-8B", weights_file="Qwen3-8B-Q4_K_M.gguf", weights_sha256="sha256:" + "d" * 64,
                    quantization="Q4_K_M", context_length=16384, tool_call_format="qwen_xml_json",
                    runtime="llama.cpp llama-server", runtime_version="b12478-8d1599fca",
                    chat_template_sha256=sha256_text(TEMPLATE), refusal_modified=False)


@pytest.fixture
def client(stub, pin):
    return LocalClient(stub.base_url, API_KEY, pin, seed=7)


def converse(client):
    return client.converse(system=SYSTEM, messages=[{"role": "user", "content": [{"text": OPENING}]}],
                           tool_config=TOOLS, inference=INFERENCE)


# --- parse_completion ---------------------------------------------------------------------------

def test_an_eos_tool_call_becomes_a_tool_use_block():
    content, stop = parse_completion('<tool_call>\n{"name": "run_command", "arguments": {"command": "ls -l"}}\n</tool_call>',
                                     "eos", id_counter())
    assert content == [{"toolUse": {"toolUseId": "id1", "name": "run_command", "input": {"command": "ls -l"}}}]
    assert stop == "tool_use"


def test_text_before_a_call_is_a_stripped_text_block():
    content, _ = parse_completion("  Let me check.\n" + TOOL_CALL_RUN, "eos", id_counter())
    assert content == [{"text": "Let me check."}, {"toolUse": {"toolUseId": "id1", "name": "run_command",
                                                              "input": {"command": "ls"}}}]


def test_text_after_a_call_is_kept_in_a_text_block():
    content, _ = parse_completion(TOOL_CALL_RUN + "\nDone then.", "eos", id_counter())
    assert {"text": "Done then."} in content
    assert {"toolUse": {"toolUseId": "id1", "name": "run_command", "input": {"command": "ls"}}} in content


def test_two_calls_give_two_tool_use_blocks_and_tool_use_stop():
    content, stop = parse_completion(TOOL_CALL_RUN + "\n" + TOOL_CALL_RUN, "eos", id_counter())
    assert [block["toolUse"]["toolUseId"] for block in content] == ["id1", "id2"]
    assert stop == "tool_use"


def test_eos_plain_text_is_an_end_turn():
    assert parse_completion("hello there", "eos", id_counter()) == ([{"text": "hello there"}], "end_turn")


@pytest.mark.parametrize("raw", ["", "  \n "])
def test_eos_empty_text_is_an_end_turn_with_no_content(raw):
    assert parse_completion(raw, "eos", id_counter()) == ([], "end_turn")


def test_a_limit_keeps_the_text_even_with_a_complete_call_inside():
    assert parse_completion(TOOL_CALL_RUN, "limit", id_counter()) == ([{"text": TOOL_CALL_RUN}], "max_tokens")


def test_a_limit_with_no_text_has_no_content():
    assert parse_completion("", "limit", id_counter()) == ([], "max_tokens")


@pytest.mark.parametrize("stop_type", ["word", "", "none"])
def test_an_unknown_stop_type_is_malformed_model_output(stop_type):
    assert parse_completion("partial", stop_type, id_counter()) == ([{"text": "partial"}], "malformed_model_output")


@pytest.mark.parametrize("raw", [
    '<tool_call>\n{not json}\n</tool_call>',
    '<tool_call>\n[1, 2]\n</tool_call>',
    '<tool_call>\n{"arguments": {"command": "ls"}}\n</tool_call>',
    '<tool_call>\n{"name": 5, "arguments": {}}\n</tool_call>',
    '<tool_call>\n{"name": "run_command"}\n</tool_call>',
    '<tool_call>\n{"name": "run_command", "arguments": {"command": "ls"}}',
    TOOL_CALL_RUN + '\n<tool_call>\n{not json}\n</tool_call>',
], ids=["invalid-json", "array", "no-name", "name-not-string", "no-arguments", "unclosed-tag", "good-then-bad"])
def test_a_call_the_parser_cannot_read_is_malformed(raw):
    assert parse_completion(raw, "eos", id_counter()) == ([{"text": raw}], "malformed_tool_use")


def test_arguments_given_as_a_json_string_stay_a_string():
    raw = call_text({"name": "run_command", "arguments": '{"command": "ls"}'})
    content, _ = parse_completion(raw, "eos", id_counter())
    assert content[0]["toolUse"]["input"] == '{"command": "ls"}'


def test_extra_keys_inside_arguments_are_kept():
    raw = call_text({"name": "run_command", "arguments": {"command": "ls", "extra": 1}})
    content, _ = parse_completion(raw, "eos", id_counter())
    assert content[0]["toolUse"]["input"] == {"command": "ls", "extra": 1}


def test_a_command_keeps_its_surrounding_whitespace_exactly():
    raw = call_text({"name": "run_command", "arguments": {"command": "  ls -l\n  "}})
    content, _ = parse_completion(raw, "eos", id_counter())
    assert content[0]["toolUse"]["input"] == {"command": "  ls -l\n  "}


# --- to_openai_tools / to_openai_messages -------------------------------------------------------

def test_tools_keep_their_names_schemas_and_type():
    tools = to_openai_tools(TOOLS)
    assert [t["function"]["name"] for t in tools] == ["run_command", "submit_flag"]
    for tool, spec in zip(tools, TOOLS["tools"]):
        assert tool["type"] == "function"
        assert tool["function"]["parameters"] == spec["toolSpec"]["inputSchema"]["json"]


def test_the_system_text_comes_first():
    out = to_openai_messages("S", [{"role": "user", "content": [{"text": "hi"}]}])
    assert out == [{"role": "system", "content": "S"}, {"role": "user", "content": "hi"}]


def test_an_assistant_tool_call_becomes_one_message_with_json_arguments():
    messages = [{"role": "assistant", "content": [
        {"text": "I will look."}, {"toolUse": {"toolUseId": "c1", "name": "run_command", "input": {"command": "ls"}}}]}]
    out = to_openai_messages("S", messages)
    assert out[1] == {"role": "assistant", "content": "I will look.", "tool_calls": [
        {"id": "c1", "type": "function", "function": {"name": "run_command", "arguments": '{"command": "ls"}'}}]}


def test_a_string_tool_input_passes_through_unchanged():
    messages = [{"role": "assistant", "content": [
        {"toolUse": {"toolUseId": "c1", "name": "run_command", "input": '{"command": "ls"}'}}]}]
    out = to_openai_messages("S", messages)
    assert out[1]["tool_calls"][0]["function"]["arguments"] == '{"command": "ls"}'


def test_two_tool_results_become_two_tool_messages_with_joined_text():
    messages = [{"role": "user", "content": [
        {"toolResult": {"toolUseId": "c1", "content": [{"text": "out one"}]}},
        {"toolResult": {"toolUseId": "c2", "content": [{"text": "line1"}, {"text": "line2"}]}}]}]
    out = to_openai_messages("S", messages)
    assert out[1:] == [{"role": "tool", "tool_call_id": "c1", "content": "out one"},
                       {"role": "tool", "tool_call_id": "c2", "content": "line1\nline2"}]


def test_a_tool_result_then_text_gives_a_tool_message_then_a_user_message():
    messages = [{"role": "user", "content": [
        {"toolResult": {"toolUseId": "c1", "content": [{"text": "out"}]}}, {"text": "thanks"}]}]
    out = to_openai_messages("S", messages)
    assert out[1:] == [{"role": "tool", "tool_call_id": "c1", "content": "out"},
                       {"role": "user", "content": "thanks"}]


def test_an_assistant_text_turn_has_no_tool_calls_key():
    out = to_openai_messages("S", [{"role": "assistant", "content": [{"text": "Hi."}]}])
    assert out[1] == {"role": "assistant", "content": "Hi."}
    assert "tool_calls" not in out[1]


# --- LocalClient construction -------------------------------------------------------------------

@pytest.mark.parametrize("url", ["http://10.0.0.5:8081", "http://example.com:8081", "http://0.0.0.0:8081"])
def test_a_non_loopback_server_is_refused(url, pin):
    with pytest.raises(ValueError):
        LocalClient(url, API_KEY, pin, seed=7)


@pytest.mark.parametrize("url", ["http://127.0.0.1:8081", "http://localhost:8081", "http://[::1]:8081"])
def test_a_loopback_server_is_accepted(url, pin):
    LocalClient(url, API_KEY, pin, seed=7)


def test_a_pin_with_another_tool_call_format_is_refused(pin):
    with pytest.raises(ValueError):
        LocalClient("http://127.0.0.1:8081", API_KEY, replace(pin, tool_call_format="other"), seed=7)


# --- converse against the stub ------------------------------------------------------------------

def test_every_request_carries_the_bearer_key(stub, client):
    converse(client)
    assert [r["headers"].get("authorization") for r in stub.requests] == [f"Bearer {API_KEY}"] * 2


def test_a_turn_is_apply_template_then_completion(stub, client):
    converse(client)
    assert stub.paths() == ["/apply-template", "/completion"]


def test_the_completion_prompt_is_the_rendered_prompt(stub, client):
    converse(client)
    assert stub.requests[1]["body"]["prompt"] == stub.requests[0]["response"]["prompt"]


def test_the_completion_carries_the_inference_fields(stub, client):
    converse(client)
    body = stub.requests[1]["body"]
    assert (body["n_predict"], body["temperature"], body["top_p"]) == (512, 0.7, 0.9)
    assert body["seed"] == 7
    assert body["stream"] is False


def test_the_completion_sets_every_sampler_field(stub, client):
    converse(client)
    body = stub.requests[1]["body"]
    for key, value in NEUTRAL_SAMPLER.items():
        assert body[key] == value, key


def test_a_pin_sampler_override_is_sent(stub, pin):
    overridden = replace(pin, sampler={**NEUTRAL_SAMPLER, "top_k": 40})
    converse(LocalClient(stub.base_url, API_KEY, overridden, seed=7))
    assert stub.requests[1]["body"]["top_k"] == 40


def test_the_reply_content_and_stop_come_from_parse_completion(stub, client):
    stub.completions.append((200, completion(TOOL_CALL_RUN)))
    reply = converse(client)
    assert reply.content == [{"toolUse": {"toolUseId": "call_1", "name": "run_command", "input": {"command": "ls"}}}]
    assert reply.stop_reason == "tool_use"


def test_the_reply_token_counts_come_from_the_server(stub, client):
    stub.completions.append((200, completion(TOOL_CALL_RUN)))
    reply = converse(client)
    assert (reply.input_tokens, reply.output_tokens) == (282, 22)


def test_the_reply_keeps_the_raw_fields_and_has_no_request_id(stub, client):
    stub.completions.append((200, completion(TOOL_CALL_RUN)))
    reply = converse(client)
    assert reply.request_id is None
    assert reply.retries == 0
    assert reply.raw_stop_reason == "eos"
    assert reply.raw_completion == TOOL_CALL_RUN


def test_tool_call_ids_are_unique_across_turns(stub, client):
    stub.completions.extend([(200, completion(TOOL_CALL_RUN)), (200, completion(TOOL_CALL_RUN))])
    first, second = converse(client), converse(client)
    assert first.tool_uses[0]["toolUseId"] == "call_1"
    assert second.tool_uses[0]["toolUseId"] == "call_2"


def test_an_exceeded_context_is_a_window_stop_not_an_error(stub, client):
    stub.completions.append((400, error_body(400, "exceed_context_size_error",
                                             "request (20000 tokens) exceeds the available context size (16384 tokens)",
                                             n_prompt_tokens=20000, n_ctx=16384)))
    reply = converse(client)
    assert reply.content == []
    assert reply.stop_reason == "model_context_window_exceeded"
    assert reply.input_tokens == 20000
    assert reply.raw_stop_reason == "exceed_context_size_error"


@pytest.mark.parametrize("status,body,kind", [
    (400, error_body(400, "invalid_request_error"), REQUEST_REJECTED),
    (404, error_body(404, "not_found_error"), REQUEST_REJECTED),
    (500, error_body(500, "server_error"), SERVICE),
    (503, error_body(503, "unavailable_error"), SERVICE),
])
def test_an_http_error_is_classified_by_status(stub, client, status, body, kind):
    stub.completions.append((status, body))
    with pytest.raises(ModelError) as info:
        converse(client)
    assert info.value.kind == kind


def test_a_wrong_key_is_a_rejected_request(stub, pin):
    with pytest.raises(ModelError) as info:
        converse(LocalClient(stub.base_url, "wrong", pin, seed=7))
    assert info.value.kind == REQUEST_REJECTED


def test_a_stopped_server_is_a_service_failure(stub, client):
    stub.close()
    with pytest.raises(ModelError) as info:
        converse(client)
    assert info.value.kind == SERVICE


def test_a_reply_that_is_not_json_is_a_service_failure(stub, client):
    stub.completions.append((200, b"not json"))
    with pytest.raises(ModelError) as info:
        converse(client)
    assert info.value.kind == SERVICE


def test_a_completion_without_content_is_an_empty_end_turn(stub, client):
    stub.completions.append((200, {"stop_type": "eos", "tokens_evaluated": 5, "tokens_predicted": 0}))
    reply = converse(client)
    assert (reply.content, reply.stop_reason) == ([], "end_turn")


def test_a_template_reply_without_a_prompt_is_a_service_failure(stub, client):
    stub.render_without_prompt = True
    with pytest.raises(ModelError) as info:
        converse(client)
    assert info.value.kind == SERVICE


# --- prepare: the live server against the pin ---------------------------------------------------

def test_prepare_returns_the_rendered_prefix_and_its_hashes(stub, client):
    facts = client.prepare(SYSTEM, TOOLS, OPENING)
    # the last RENDERING request (the over-window self-test comes after it and has no prompt in its answer)
    prefix = [r for r in stub.requests if r["path"] == "/apply-template"][-1]["response"]["prompt"]
    assert facts["rendered_prefix"] == prefix
    assert SYSTEM in prefix and OPENING in prefix and "run_command" in prefix
    assert facts["build_info"] == "b12478-8d1599fca"
    assert facts["chat_template_sha256"] == sha256_text(TEMPLATE)
    assert facts["rendered_prefix_sha256"] == sha256_text(prefix)


def test_local_runtime_has_zero_hashes_before_prepare(client):
    runtime = client.local_runtime
    assert runtime["chat_template_sha256"] == ZERO_HASH
    assert runtime["rendered_prefix_sha256"] == ZERO_HASH


def test_local_runtime_holds_the_live_hashes_after_prepare(client, pin):
    facts = client.prepare(SYSTEM, TOOLS, OPENING)
    assert client.local_runtime == {
        "runtime": pin.runtime, "runtime_version": pin.runtime_version, "weights_sha256": pin.weights_sha256,
        "quantization": pin.quantization, "context_length": pin.context_length, "seed": 7,
        "chat_template_sha256": sha256_text(TEMPLATE),
        "rendered_prefix_sha256": sha256_text(facts["rendered_prefix"]), "refusal_modified": False}


def local_manifest(manifest, client, pin):
    local = copy.deepcopy(manifest)
    del local["region"]
    local.update(backend="local", model_id=pin.model_id, local_runtime=client.local_runtime)
    return local


def test_a_local_manifest_validates_before_and_after_prepare(manifest, client, pin):
    assert telemetry.validate_record("manifest", local_manifest(manifest, client, pin)) == []
    client.prepare(SYSTEM, TOOLS, OPENING)
    assert telemetry.validate_record("manifest", local_manifest(manifest, client, pin)) == []


@pytest.mark.parametrize("fragment,drift", [
    ("build", lambda s: s.props.update(build_info="b11111-0000000")),
    ("weights", lambda s: s.props.update(model_path="C:\\models\\other.gguf")),
    ("window", lambda s: s.props.update(default_generation_settings={"n_ctx": 8192})),
    ("slots", lambda s: s.props.update(total_slots=2)),
    ("chat template", lambda s: s.props.update(chat_template=TEMPLATE + " changed")),
    ("default system prompt", lambda s: setattr(s, "system_before_user", True)),
], ids=["build", "weights", "window", "slots", "template", "system-block"])
def test_prepare_refuses_a_server_that_differs_from_the_pin(stub, client, fragment, drift):
    drift(stub)
    with pytest.raises(ServerCheckError, match=fragment):
        client.prepare(SYSTEM, TOOLS, OPENING)


def test_prepare_refuses_a_stopped_server(stub, client):
    stub.close()
    with pytest.raises(ServerCheckError, match="could not be queried"):
        client.prepare(SYSTEM, TOOLS, OPENING)


def test_prepare_refuses_a_wrong_key(stub, pin):
    with pytest.raises(ServerCheckError, match="could not be queried"):
        LocalClient(stub.base_url, "wrong", pin, seed=7).prepare(SYSTEM, TOOLS, OPENING)


# --- weights and the pin file -------------------------------------------------------------------

def test_verify_weights_accepts_the_pinned_hash(tmp_path):
    path = tmp_path / "weights.gguf"
    path.write_bytes(b"hello")
    verify_weights(path, "sha256:" + hashlib.sha256(b"hello").hexdigest())


def test_verify_weights_refuses_another_hash(tmp_path):
    path = tmp_path / "weights.gguf"
    path.write_bytes(b"hello")
    with pytest.raises(ServerCheckError, match="does not match"):
        verify_weights(path, "sha256:" + "0" * 64)


def test_a_pin_round_trips_through_a_json_file(tmp_path, pin):
    path = tmp_path / "pin.json"
    path.write_text(json.dumps(asdict(pin)), encoding="utf-8")
    assert LocalPin.from_file(path) == pin


def test_a_pin_file_with_an_unknown_key_is_refused(tmp_path, pin):
    path = tmp_path / "pin.json"
    path.write_text(json.dumps({**asdict(pin), "extra": 1}), encoding="utf-8")
    with pytest.raises(TypeError):
        LocalPin.from_file(path)


def test_the_sampler_defaults_to_the_neutral_sampler(pin):
    assert pin.sampler == NEUTRAL_SAMPLER


# --- the end-to-end loop on the stub ------------------------------------------------------------

def run_scripted(stub, client, replies):
    stub.completions.extend((200, reply) for reply in replies)
    clock = FakeClock()
    executor = FakeExecutor(clock, [outcome("notes.txt\n")])
    steps: list[dict] = []
    result = run_agent(model=client, executor=executor, prompts=load_prompts(), condition="no_hint",
                       run_id=RUN_ID, secrets=SECRETS, clock=clock, health=lambda: True, on_step=steps.append)
    return result, steps


def test_a_tool_call_then_text_is_two_steps(stub, client):
    result, steps = run_scripted(stub, client, [completion(TOOL_CALL_RUN), completion("All done.")])
    assert len(steps) == 2
    assert result.termination_reason == "agent_stopped"


def test_the_command_step_keeps_the_raw_completion(stub, client):
    _, steps = run_scripted(stub, client, [completion(TOOL_CALL_RUN), completion("All done.")])
    first = steps[0]
    assert (first["tool_name"], first["raw_stop_reason"], first["raw_completion"]) == ("run_command", "eos", TOOL_CALL_RUN)
    assert "bedrock_request_id" not in first


def test_the_text_step_is_a_text_only_turn(stub, client):
    _, steps = run_scripted(stub, client, [completion(TOOL_CALL_RUN), completion("All done.")])
    assert steps[1]["tool_name"] is None
    assert steps[1]["stop_reason"] == "end_turn"


def test_every_step_of_the_loop_validates(stub, client):
    _, steps = run_scripted(stub, client, [completion(TOOL_CALL_RUN), completion("All done.")])
    for step in steps:
        assert telemetry.validate_record("step", step) == []


def test_the_second_request_carries_the_tool_call_and_its_result(stub, client):
    run_scripted(stub, client, [completion(TOOL_CALL_RUN), completion("All done.")])
    second = [r["body"] for r in stub.requests if r["path"] == "/apply-template"][1]["messages"]
    assistant = [m for m in second if m["role"] == "assistant"][0]
    tool = [m for m in second if m["role"] == "tool"][0]
    assert assistant["tool_calls"][0]["id"] == "call_1"
    assert (tool["tool_call_id"], tool["content"]) == ("call_1", "notes.txt\n")


def test_a_local_run_passes_the_cross_record_checks(stub, client, manifest, pin):
    result, steps = run_scripted(stub, client, [completion(TOOL_CALL_RUN), completion("All done.")])
    local = local_manifest(manifest, client, pin)
    local["termination_reason"] = result.termination_reason
    assert telemetry.check_consistency(local, steps, [], None) == []


def test_an_unclosed_call_is_an_unusable_output_and_the_run_continues(stub, client):
    result, steps = run_scripted(stub, client, [completion(UNCLOSED_CALL), completion("All done.")])
    assert len(steps) == 2
    assert steps[0]["tool_call_error"] == "unusable_output"
    assert steps[0]["raw_completion"] == UNCLOSED_CALL
    assert result.termination_reason == "agent_stopped"


# --- found by the test worker, fixed in the module --------------------------------------------

def test_a_good_call_followed_by_an_unclosed_tag_is_malformed_not_silently_trimmed():
    # A complete call and then a broken fragment: executing the good one and dropping the rest would repair the
    # model's output, which this client promises never to do.
    raw = TOOL_CALL_RUN + '\n<tool_call>\n{"name": "run_command"'
    assert parse_completion(raw, "eos", id_counter()) == ([{"text": raw}], "malformed_tool_use")


def test_a_stray_closing_tag_after_a_good_call_is_malformed_too():
    raw = TOOL_CALL_RUN + "\n</tool_call>"
    assert parse_completion(raw, "eos", id_counter()) == ([{"text": raw}], "malformed_tool_use")


def test_prepare_reports_a_missing_prompt_as_a_server_check_error_not_a_key_error(stub, client):
    stub.render_without_prompt = True            # /apply-template answers {} with no "prompt"
    with pytest.raises(ServerCheckError, match="returned no prompt"):
        client.prepare(SYSTEM, TOOLS, OPENING)


@pytest.mark.parametrize("path", ["C:\\models\\Qwen3-8B-Q4_K_M.gguf", "/home/someone/models/Qwen3-8B-Q4_K_M.gguf"])
def test_the_weights_file_is_compared_by_name_whatever_path_style_the_server_reports(stub, client, path):
    stub.props["model_path"] = path
    client.prepare(SYSTEM, TOOLS, OPENING)       # does not raise


# --- the committed pin (D-068) and the points where a second model would plug in ---------------------

import dataclasses  # noqa: E402
import re  # noqa: E402

import local_model  # noqa: E402


def test_the_committed_pin_loads_and_says_what_the_decision_log_says():
    pin = LocalPin.from_file()
    assert (pin.model_id, pin.weights_file, pin.quantization, pin.context_length) == ("Qwen/Qwen3-8B", "Qwen3-8B-Q4_K_M.gguf", "Q4_K_M", 24576)
    assert pin.weights_sha256 == "sha256:d98cdcbd03e17ce47681435b5150e34c1417f50b5c0019dd560e4882c5745785"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", pin.chat_template_sha256)
    assert (pin.runtime, pin.runtime_version, pin.refusal_modified) == ("llama.cpp llama-server", "b12478-8d1599fca", False)


def test_the_committed_pin_leaves_nothing_to_the_servers_defaults():
    pin = LocalPin.from_file()
    assert pin.sampler == NEUTRAL_SAMPLER                       # top_k 0, min_p 0, no penalties, prompt cache on
    assert pin.tool_call_format in local_model.TOOL_CALL_PARSERS


def test_the_committed_pins_server_flags_match_its_own_numbers_and_the_flags_that_must_never_be_dropped():
    pin = LocalPin.from_file()
    flags = pin.server_flags
    assert flags[flags.index("-c") + 1] == str(pin.context_length)          # the window the pin says is the window the flags ask for
    assert flags[flags.index("--parallel") + 1] == "1"                      # extra slots would split the window
    assert "--no-context-shift" in flags                                    # a full window must be an error, not a silent eviction
    assert flags[flags.index("--host") + 1] == "127.0.0.1"                  # loopback only
    assert "--api-key-file" in flags and "--no-webui" in flags
    assert flags[flags.index("--reasoning") + 1] == "off"                   # thinking mode off (D-067)


def test_an_older_pin_file_without_the_newer_fields_still_loads_with_their_defaults(tmp_path):
    data = dataclasses.asdict(LocalPin.from_file())
    del data["user_turn_start"], data["server_flags"]
    path = tmp_path / "pin.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    loaded = LocalPin.from_file(path)
    assert loaded.user_turn_start == "<|im_start|>user\n" and loaded.server_flags == []


def test_the_user_turn_marker_comes_from_the_pin_not_from_the_code(stub, pin):
    other = dataclasses.replace(pin, user_turn_start="<|user|>")
    with pytest.raises(ServerCheckError, match="default system prompt"):
        LocalClient(stub.base_url, API_KEY, other, seed=1).prepare(SYSTEM, TOOLS, OPENING)
    LocalClient(stub.base_url, API_KEY, pin, seed=1).prepare(SYSTEM, TOOLS, OPENING)       # the stub's own marker passes


def test_an_unknown_tool_call_format_names_the_ones_that_exist(stub, pin):
    with pytest.raises(ValueError, match="qwen_xml_json"):
        LocalClient(stub.base_url, API_KEY, dataclasses.replace(pin, tool_call_format="mystery"), seed=1)


def test_a_second_models_parser_plugs_in_by_name_alone(stub, pin, monkeypatch):
    monkeypatch.setitem(local_model.TOOL_CALL_PARSERS, "other_family", lambda raw, stop_type, make_id: ([{"text": "PARSED:" + raw}], "end_turn"))
    stub.completions.append((200, completion("raw words")))
    reply = converse(LocalClient(stub.base_url, API_KEY, dataclasses.replace(pin, tool_call_format="other_family"), seed=1))
    assert reply.content == [{"text": "PARSED:raw words"}] and reply.raw_completion == "raw words"


# --- the containment audit's findings (D-069) -------------------------------------------------------

def pinned_for(pin, stub, system=SYSTEM):
    """The pin with the stub's own rendering of `system` pinned, as the committed pin pins the real server's."""
    rendered = stub.render({"messages": [{"role": "system", "content": system}, {"role": "user", "content": OPENING}], "tools": to_openai_tools(TOOLS)})
    return dataclasses.replace(pin, rendered_prefixes={sha256_text(system): sha256_text(rendered)})


def test_the_server_must_refuse_an_over_window_prompt_or_the_run_cannot_start(stub, pin):
    stub.shift_on = True            # a server that ACCEPTS an oversized prompt (truncating it) is not one the context limit can be detected on
    with pytest.raises(ServerCheckError, match="accepted a prompt far over its window"):
        LocalClient(stub.base_url, API_KEY, pin, seed=1).prepare(SYSTEM, TOOLS, OPENING)


def test_the_self_test_sends_one_token_to_predict_so_nothing_is_generated_if_it_fails(stub, pin):
    LocalClient(stub.base_url, API_KEY, pin, seed=1).prepare(SYSTEM, TOOLS, OPENING)
    selftest = [r["body"] for r in stub.requests if r["path"] == "/completion"][0]
    assert selftest["n_predict"] == 1 and len(selftest["prompt"]) > 2 * pin.context_length


def test_any_other_answer_to_the_self_test_is_not_taken_for_the_refusal(stub, pin):
    stub.overflow_status = 500
    with pytest.raises(ServerCheckError, match="not the context-size refusal"):
        LocalClient(stub.base_url, API_KEY, pin, seed=1).prepare(SYSTEM, TOOLS, OPENING)


def test_a_pinned_rendered_prefix_that_matches_passes_and_is_reported_as_pinned(stub, pin):
    facts = LocalClient(stub.base_url, API_KEY, pinned_for(pin, stub), seed=1).prepare(SYSTEM, TOOLS, OPENING)
    assert facts["prefix_pinned"] is True and facts["process_verified"] is True


def test_a_rendering_that_differs_from_the_pin_stops_the_run(stub, pin):
    pinned = pinned_for(pin, stub)
    stub.tools_marker = "<tool_defs>"   # the same server, "restarted" so that it now renders differently (a flag or a template change)
    with pytest.raises(ServerCheckError, match="differs from the pin"):
        LocalClient(stub.base_url, API_KEY, pinned, seed=1).prepare(SYSTEM, TOOLS, OPENING)


def test_a_system_prompt_with_no_pinned_rendering_stops_the_run(stub, pin):
    with pytest.raises(ServerCheckError, match="re-pin"):
        LocalClient(stub.base_url, API_KEY, pinned_for(pin, stub), seed=1).prepare("a different system prompt", TOOLS, OPENING)


def test_an_unpinned_prefix_is_reported_as_unpinned_not_silently_accepted(stub, pin):
    assert pin.rendered_prefixes is None
    assert LocalClient(stub.base_url, API_KEY, pin, seed=1).prepare(SYSTEM, TOOLS, OPENING)["prefix_pinned"] is False


def test_the_committed_pin_pins_the_rendering_of_both_conditions_of_the_committed_prompts():
    # If a prompt file changes, the manifest's system_prompt_hash changes and this fails until the pin is renewed:
    # the prompts freeze at pre-registration and the pin has to move with any superseding change.
    pin = LocalPin.from_file()
    prompts = load_prompts()
    assert set(pin.rendered_prefixes) == {prompts.system_prompt_hash("no_hint"), prompts.system_prompt_hash("hint")}
    assert all(re.fullmatch(r"sha256:[0-9a-f]{64}", v) for v in pin.rendered_prefixes.values())
    assert len(set(pin.rendered_prefixes.values())) == 2                    # the hint changes what the model is shown


def test_the_committed_pin_has_prompt_caching_off():
    assert LocalPin.from_file().sampler["cache_prompt"] is False and NEUTRAL_SAMPLER["cache_prompt"] is False


def test_the_client_ignores_the_machines_proxy_settings(stub, pin, monkeypatch):
    # The bearer key and every prompt (tool results can hold the flag) must never pass through a proxy.
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")                      # a dead proxy: any use of it fails the call
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    reply = converse(LocalClient(stub.base_url, API_KEY, pin, seed=1))
    assert reply.stop_reason == "end_turn"


def test_the_per_call_timeout_is_bounded():
    assert local_model.CALL_TIMEOUT_S <= 300


# --- the server PROCESS: the flags the server cannot report about itself (D-069) -----------------------

import os  # noqa: E402
import socket  # noqa: E402
import sys as _sys  # noqa: E402

EXE = "C:\\runtime\\llama-server.exe"
KEYFILE = "C:\\keys\\api_key.txt"


def committed_command_line(flags=None, weights="C:\\models\\Qwen3-8B-Q4_K_M.gguf", exe=EXE):
    """The command line the operator script (harness/local_server.ps1) builds from the committed pin."""
    flags = list(LocalPin.from_file().server_flags if flags is None else flags)
    args = ["-m", weights] + [KEYFILE if f == "<file>" else f for f in flags]
    return f'"{exe}" ' + " ".join(args)


def good_facts(**changes):
    return {"pid": 4242, "path": EXE, "address": "127.0.0.1", "command_line": committed_command_line(), **changes}


def test_the_command_line_the_operator_script_builds_from_the_pin_passes():
    problems, weights = local_model.check_process(LocalPin.from_file(), good_facts())
    assert problems == [] and weights == "C:\\models\\Qwen3-8B-Q4_K_M.gguf"


@pytest.mark.parametrize("flags,fragment", [
    (lambda f: [x for x in f if x != "--no-context-shift"], "different flags"),                   # context shift left on
    (lambda f: ["-ctk", "q4_0" if x == "q8_0" else x] if False else [("q4_0" if x == "q8_0" else x) for x in f], "different flags"),  # KV type
    (lambda f: [("on" if x == "off" else x) for x in f], "different flags"),                      # thinking mode
    (lambda f: [("2" if x == "1" else x) for x in f], "different flags"),                         # slots split the window
    (lambda f: [("32768" if x == "24576" else x) for x in f], "different flags"),                 # a different window
    (lambda f: f + ["--props"], "different flags"),                                               # an extra endpoint switched on
    (lambda f: [("0.0.0.0" if x == "127.0.0.1" else x) for x in f], "different flags"),           # asked to bind wide
])
def test_a_server_started_with_different_flags_is_refused(flags, fragment):
    pin = LocalPin.from_file()
    facts = good_facts(command_line=committed_command_line(flags(list(pin.server_flags))))
    problems, _ = local_model.check_process(pin, facts)
    assert any(fragment in p for p in problems), problems


@pytest.mark.parametrize("address", ["0.0.0.0", "192.168.1.20", "::", ""])
def test_a_server_bound_beyond_loopback_is_refused(address):
    problems, _ = local_model.check_process(LocalPin.from_file(), good_facts(address=address))
    assert any("not only on loopback" in p for p in problems), problems


def test_a_different_weights_file_is_refused():
    problems, weights = local_model.check_process(LocalPin.from_file(), good_facts(command_line=committed_command_line(weights="C:\\models\\other.gguf")))
    assert any("pinned weights file" in p for p in problems) and weights == "C:\\models\\other.gguf"


def test_a_process_that_is_not_llama_server_is_refused():
    problems, _ = local_model.check_process(LocalPin.from_file(), good_facts(command_line=committed_command_line(exe="C:\\tools\\other-server.exe")))
    assert any("not llama-server" in p for p in problems), problems


@pytest.mark.parametrize("facts", [{}, good_facts(command_line=""), good_facts(command_line=None)])
def test_nothing_listening_or_an_unreadable_command_line_is_refused(facts):
    problems, weights = local_model.check_process(LocalPin.from_file(), facts)
    assert problems and weights is None


def test_prepare_refuses_a_server_whose_process_does_not_match_the_pin(stub, pin, monkeypatch):
    monkeypatch.setattr(local_model, "inspect_server_process", lambda port: good_facts(address="0.0.0.0", command_line=committed_command_line()))
    with pytest.raises(ServerCheckError, match="not only on loopback"):
        LocalClient(stub.base_url, API_KEY, dataclasses.replace(pin, server_flags=list(LocalPin.from_file().server_flags)), seed=1).prepare(SYSTEM, TOOLS, OPENING)


def test_prepare_hands_back_the_weights_path_the_server_was_started_with(stub, pin):
    facts = LocalClient(stub.base_url, API_KEY, pin, seed=1).prepare(SYSTEM, TOOLS, OPENING)
    assert facts["weights_path"] == "C:\\models\\Qwen3-8B-Q4_K_M.gguf" and facts["process_verified"] is True


def test_the_over_window_test_is_honest_about_what_it_proves():
    # Checked live against llama.cpp b12478: an over-long PROMPT is refused whether or not context shift is on (shift acts on a
    # growing REPLY), so this test cannot detect shift, and says so. Shift is checked through the process's command line.
    text = (local_model.LocalClient._window_selftest.__doc__ or "")
    assert "does NOT test context shift" in text


@pytest.mark.skipif(_sys.platform != "win32", reason="the server's process is inspected through PowerShell on the Windows host (D-059)")
def test_the_real_inspector_reads_the_process_that_owns_a_listening_port():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        port = listener.getsockname()[1]
        facts = _REAL_INSPECTOR(port)
        assert facts["pid"] == os.getpid() and facts["address"] == "127.0.0.1"
        assert "python" in facts["command_line"].lower() and facts["path"]
    finally:
        listener.close()


@pytest.mark.skipif(_sys.platform != "win32", reason="the server's process is inspected through PowerShell on the Windows host (D-059)")
def test_the_real_inspector_returns_nothing_for_a_port_nobody_listens_on():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()                                   # a port that was just free, with nothing on it
    assert _REAL_INSPECTOR(port) == {}


# --- where the URL, key file and pin come from (so the scripts need no arguments) -------------------

from pathlib import Path  # noqa: E402


def test_the_settings_default_to_the_documented_locations():
    url, key_file, pin_file = local_model.local_settings({})
    assert url == "http://127.0.0.1:8081" and key_file == Path("G:/model-eval-local/server/api_key.txt") and pin_file is None


def test_the_settings_can_be_overridden_from_the_environment_file():
    url, key_file, pin_file = local_model.local_settings({"LOCAL_LLM_URL": "http://localhost:9000", "LOCAL_LLM_KEY_FILE": "C:/k/key.txt",
                                                          "LOCAL_LLM_PIN": "harness/other_pin.json"})
    assert (url, key_file, pin_file) == ("http://localhost:9000", Path("C:/k/key.txt"), Path("harness/other_pin.json"))


def test_the_check_and_spike_scripts_import_and_take_no_required_arguments():
    import local_check
    import local_spike
    for module in (local_check, local_spike):
        assert callable(module.main)
