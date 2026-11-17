"""A locally served open-weight model behind the same seam as Bedrock (D-060, D-067).

The runtime is llama.cpp's `llama-server`, and the route is deliberately the transparent one:

    1. `POST /apply-template`   the runtime renders the conversation with the model's OWN chat template
                                (the exact prompt, so the leak scan and the rendered-prefix hash see what the
                                model sees);
    2. `POST /completion`       the raw text comes back, with no grammar, no repair and no tool-call parsing;
    3. this module parses tool calls itself, strictly, the way the loop treats Bedrock's (D-063).

`/v1/chat/completions` would be easier, but with `--jinja` the runtime constrains and parses tool calls
for the model. That would make the model look more reliable here than on Bedrock, and it would hide the raw
text D-060 requires every step to keep. The server's DEFAULT sampler also differs from Converse (it adds
top_k 40 and min_p 0.05 and defaults to temperature 0.8), so every sampler field is set explicitly from the
pin. Verified against build b12478 on 2026-11-17: `/completion` on the rendered prompt reports the same prompt
token count as the chat endpoint.

Containment: the client refuses any URL that is not loopback, and the lab network has no route to the host at
all (D-066), so the agent can never reach this server. The API key is read from a file outside the repo.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from model import REQUEST_REJECTED, SERVICE, ModelError, ModelReply

ROOT = Path(__file__).resolve().parent.parent
PIN_PATH = ROOT / "harness" / "local_pin.json"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
LOOPBACK_ADDRESSES = {"127.0.0.1", "::1"}
ZERO_HASH = "sha256:" + "0" * 64     # "not available" in a manifest field that must hold a hash
CALL_TIMEOUT_S = 300                  # a 21K-token prefill takes about 16 s and a full reply about 25 s: this is generous
# An opener that ignores HTTP(S)_PROXY and the Windows proxy settings: the bearer key and every prompt go to the
# loopback address directly, never through whatever proxy the machine is configured with (D-069).
NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
TOOL_CALL = re.compile(r"<tool_call>\s*(.*?)\s*</tool_call>", re.DOTALL)

# Sampler fields every request carries, so nothing is left to the server's defaults. These match what
# Converse applies (temperature and top-p only) by switching the server's extras off. A pin may override.
NEUTRAL_SAMPLER = {"top_k": 0, "min_p": 0.0, "typical_p": 1.0, "repeat_penalty": 1.0, "presence_penalty": 0.0,
                   "frequency_penalty": 0.0, "mirostat": 0, "dry_multiplier": 0.0, "xtc_probability": 0.0,
                   # Off (D-069): a reused prompt cache makes one request's numbers depend on earlier ones, so a seed would
                   # no longer mean the same thing in every run, and the previous run's tool results (which can hold the
                   # flag) would stay in a reusable cache. It costs a full prefill per step.
                   "cache_prompt": False}


# Where the operator script and D-067 put things. .env (LOCAL_LLM_URL, LOCAL_LLM_KEY_FILE, LOCAL_LLM_PIN) overrides them.
DEFAULT_URL = "http://127.0.0.1:8081"
DEFAULT_KEY_FILE = "G:/model-eval-local/server/api_key.txt"


def local_settings(env: dict | None = None) -> tuple[str, Path, Path | None]:
    """(server URL, key file, pin file or None for the committed one). `env` defaults to .env over .env.example."""
    if env is None:
        sys.path.insert(0, str(ROOT / "harness"))
        from smoke_test import load_env
        env = {**load_env(ROOT / ".env.example"), **load_env(ROOT / ".env")}
    pin_file = env.get("LOCAL_LLM_PIN")
    return env.get("LOCAL_LLM_URL", DEFAULT_URL), Path(env.get("LOCAL_LLM_KEY_FILE", DEFAULT_KEY_FILE)), Path(pin_file) if pin_file else None


class ServerCheckError(Exception):
    """The local server is not what the pin says it is, or cannot be reached: the run cannot start."""


@dataclass(frozen=True)
class LocalPin:
    """Everything that can change what the local model does, pinned (D-060). Written once, after the spike."""

    model_id: str                 # the model's published name
    weights_file: str             # file name the server must report for the weights
    weights_sha256: str           # "sha256:..." of that file
    quantization: str
    context_length: int           # the window the server is started with (-c), per slot
    tool_call_format: str         # how this model writes tool calls; only "qwen_xml_json" is implemented
    runtime: str
    runtime_version: str          # must equal the server's reported build_info
    chat_template_sha256: str     # "sha256:..." of the template text the server reports
    refusal_modified: bool
    sampler: dict = field(default_factory=lambda: dict(NEUTRAL_SAMPLER))
    # How this model's template opens a user turn. A bare user message must render starting with exactly this, or the
    # runtime has put text in front of it (a default system prompt). It is the template's, so it is the pin's.
    user_turn_start: str = "<|im_start|>user\n"
    # How the server was started. Documentation for whoever restarts it: the client cannot read these back, and
    # the ones that change what the model sees show up in the rendered-prefix hash (reasoning) or the checked
    # window and slot count (-c, --parallel).
    server_flags: list = field(default_factory=list)
    # The rendered request prefix (system text + tools + opening message, as the runtime renders it), pinned per system
    # text: {sha256 of the system text: sha256 of the rendering}. This is the check that catches a server restarted with
    # different flags (thinking mode, a different template) or a changed prompt, none of which the other checks can see.
    # None means unpinned; the committed pin always has it (tests/test_local_model.py).
    rendered_prefixes: dict | None = None

    @staticmethod
    def from_file(path: Path = PIN_PATH) -> "LocalPin":
        data = json.loads(path.read_text(encoding="utf-8"))
        return LocalPin(**data)


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


# --- Converse shape <-> OpenAI shape (what /apply-template accepts) -----------------------------

def to_openai_tools(tool_config: dict) -> list[dict]:
    return [{"type": "function", "function": {"name": t["toolSpec"]["name"], "description": t["toolSpec"]["description"],
                                              "parameters": t["toolSpec"]["inputSchema"]["json"]}}
            for t in tool_config["tools"]]


def to_openai_messages(system: str, messages: list[dict]) -> list[dict]:
    """The conversation as the runtime's template wants it. Tool arguments go as a JSON string, the OpenAI
    shape; an argument value that is not an object (a malformed call kept in the history) is passed through
    as given, never repaired."""
    out: list[dict] = [{"role": "system", "content": system}]
    for message in messages:
        blocks = message["content"]
        if message["role"] == "assistant":
            text = "\n".join(b["text"] for b in blocks if "text" in b)
            calls = [b["toolUse"] for b in blocks if "toolUse" in b]
            entry: dict = {"role": "assistant", "content": text}
            if calls:
                entry["tool_calls"] = [{"id": c["toolUseId"], "type": "function", "function": {
                    "name": c["name"], "arguments": c["input"] if isinstance(c["input"], str) else json.dumps(c["input"])}}
                    for c in calls]
            out.append(entry)
            continue
        texts = []
        for block in blocks:
            if "toolResult" in block:
                result = block["toolResult"]
                out.append({"role": "tool", "tool_call_id": result["toolUseId"],
                            "content": "\n".join(part["text"] for part in result["content"] if "text" in part)})
            elif "text" in block:
                texts.append(block["text"])
        if texts:
            out.append({"role": "user", "content": "\n".join(texts)})
    return out


# --- the strict parser for how Qwen-family models write a tool call ------------------------------

def parse_completion(raw: str, stop_type: str, make_id) -> tuple[list[dict], str]:
    """Return (Converse content blocks, Converse stop reason) for the model's raw text.

    Nothing is repaired. A call is well formed only if the text between its tags is a JSON object with a
    string `name` and an `arguments` member; the loop then applies D-063's own strictness on top. Anything the
    parser cannot read as a tool call makes the whole turn `malformed_tool_use`, kept as plain text so the
    loop records it and answers with the fixed error."""
    if stop_type == "limit":
        return ([{"text": raw}] if raw else []), "max_tokens"
    if stop_type != "eos":
        return ([{"text": raw}] if raw else []), "malformed_model_output"
    matches = list(TOOL_CALL.finditer(raw))
    if not matches:
        if "<tool_call>" in raw:                       # an opening tag that never closed
            return [{"text": raw}], "malformed_tool_use"
        return ([{"text": raw}] if raw.strip() else []), "end_turn"
    calls: list[dict] = []
    for match in matches:
        try:
            body = json.loads(match.group(1))
        except json.JSONDecodeError:
            return [{"text": raw}], "malformed_tool_use"
        if not isinstance(body, dict) or not isinstance(body.get("name"), str) or "arguments" not in body:
            return [{"text": raw}], "malformed_tool_use"
        calls.append({"toolUse": {"toolUseId": make_id(), "name": body["name"], "input": body["arguments"]}})
    outside = TOOL_CALL.sub("", raw)
    if "<tool_call>" in outside or "</tool_call>" in outside:      # a good call, then a broken or stray tag
        return [{"text": raw}], "malformed_tool_use"
    outside = outside.strip()
    return ([{"text": outside}] if outside else []) + calls, "tool_use"


# One parser per way a model family writes a tool call. Adding a model that writes calls differently is one function
# with the signature of parse_completion and one line here; the pin names which one applies.
TOOL_CALL_PARSERS = {"qwen_xml_json": parse_completion}


# --- the server PROCESS: what the server cannot tell us about itself --------------------------------

def inspect_server_process(port: int) -> dict:
    """The process that listens on `port`: its pid, executable, full command line and listening address ({} if none).

    A server cannot report most of its own flags (KV-cache type, context shift, slot count, thinking mode), but the
    operating system knows the command line it was started with, and which address it is bound to. This project runs on
    one Windows host (D-059), so PowerShell is the instrument."""
    script = (f"$c = Get-NetTCPConnection -LocalPort {int(port)} -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1; "
              "if (-not $c) { '{}'; exit }; "
              "$p = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $c.OwningProcess); "
              "@{pid=$p.ProcessId; path=$p.ExecutablePath; command_line=$p.CommandLine; address=$c.LocalAddress} | ConvertTo-Json -Compress")
    try:
        done = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True,
                              timeout=60, shell=False)
        return json.loads(done.stdout or "{}")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as err:
        raise ServerCheckError(f"could not inspect the model server's process: {err}") from None


def check_process(pin: LocalPin, facts: dict) -> tuple[list[str], str | None]:
    """(problems, the weights path the server was started with). Pure: judges what inspect_server_process found.

    The pin's `server_flags` are the flags the operator script passes (`<file>` stands for the key file). The process's
    command line must be exactly those plus `-m <weights>` and the key-file path, in the same order, so a server
    started by hand with a different KV type, with context shift left on, or on a wider address, is refused here."""
    if not facts:
        return ["no process listens on the server's port"], None
    problems: list[str] = []
    if facts.get("address") not in LOOPBACK_ADDRESSES:
        problems.append(f"the server listens on {facts.get('address')!r}, not only on loopback")
    try:
        tokens = [t.strip('"') for t in shlex.split(facts.get("command_line") or "", posix=False)]
    except ValueError:
        return problems + ["the server's command line could not be read"], None
    if not tokens or Path(tokens[0].replace("\\", "/")).name.lower() != "llama-server.exe":
        problems.append("the process on the port is not llama-server")
    actual, weights_path, i = [], None, 1
    while i < len(tokens):
        if tokens[i] == "-m" and i + 1 < len(tokens):
            weights_path, i = tokens[i + 1], i + 2
        elif tokens[i] == "--api-key-file" and i + 1 < len(tokens):
            actual += [tokens[i], "<file>"]
            i += 2
        else:
            actual.append(tokens[i])
            i += 1
    if actual != list(pin.server_flags):
        problems.append(f"the server was started with different flags than the pin: {actual} (pinned {list(pin.server_flags)})")
    if weights_path is None or re.split(r"[\\/]", weights_path)[-1] != pin.weights_file:
        problems.append(f"the server was not started with the pinned weights file {pin.weights_file!r}")
    return problems, weights_path


# --- the client -----------------------------------------------------------------------------------

class LocalClient:
    backend = "local"

    def __init__(self, base_url: str, api_key: str, pin: LocalPin, seed: int, *, opener=NO_PROXY_OPENER.open,
                 timeout: float = CALL_TIMEOUT_S) -> None:
        host = urlparse(base_url).hostname or ""
        if host not in LOOPBACK_HOSTS:
            raise ValueError(f"the model server must be on the loopback interface, not {host!r}")
        if pin.tool_call_format not in TOOL_CALL_PARSERS:
            raise ValueError(f"no tool-call parser for format {pin.tool_call_format!r}; known: {sorted(TOOL_CALL_PARSERS)}")
        self.base_url, self._key, self.pin, self.seed = base_url.rstrip("/"), api_key, pin, seed
        self._opener, self._timeout, self._calls = opener, timeout, 0
        self.model_id = pin.model_id
        self._facts: dict = {}        # filled by prepare(): what the live server reported

    # ---- HTTP ----
    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(self.base_url + path, data=data, method=method, headers={
            "Content-Type": "application/json", "Authorization": f"Bearer {self._key}"})
        try:
            with self._opener(request, timeout=self._timeout) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as err:
            raw = err.read().decode("utf-8", errors="replace")
            try:
                detail = json.loads(raw).get("error", {})
            except (json.JSONDecodeError, AttributeError):
                detail = {}
            err.detail = detail if isinstance(detail, dict) else {}
            raise
        except json.JSONDecodeError as err:
            raise ModelError(f"the server's reply was not JSON: {err}", kind=SERVICE) from None

    # ---- checks before a run ----
    def prepare(self, system: str, tool_config: dict, opening: str) -> dict:
        """Check the live server against the pin and render the fixed request prefix. Raises ServerCheckError.

        Returns the rendered prefix, so the caller can run the leak scan on it (D-060: for a local model the scan
        covers the request as the runtime renders it)."""
        try:
            props = self._request("GET", "/props")
            bare = self._request("POST", "/apply-template", {"messages": [{"role": "user", "content": "x"}]})
            prefix = self._request("POST", "/apply-template", {
                "messages": to_openai_messages(system, [{"role": "user", "content": [{"text": opening}]}]),
                "tools": to_openai_tools(tool_config)})
        except (urllib.error.URLError, OSError, ModelError) as err:
            raise ServerCheckError(f"the model server could not be queried: {err}") from None
        if not isinstance(prefix.get("prompt"), str) or not isinstance(bare.get("prompt"), str):
            raise ServerCheckError("the model server's /apply-template returned no prompt")
        problems = []
        pin = self.pin
        process_problems, weights_path = check_process(pin, inspect_server_process(urlparse(self.base_url).port or 80))
        problems += process_problems
        settings = props.get("default_generation_settings", {})
        # The server may be a Windows process reporting a backslash path while this runs elsewhere: split on both.
        reported_file = re.split(r"[\\/]", props.get("model_path", ""))[-1]
        if props.get("build_info") != pin.runtime_version:
            problems.append(f"build {props.get('build_info')!r}, pinned {pin.runtime_version!r}")
        if reported_file != pin.weights_file:
            problems.append(f"weights {reported_file!r}, pinned {pin.weights_file!r}")
        if settings.get("n_ctx") != pin.context_length:
            problems.append(f"window {settings.get('n_ctx')}, pinned {pin.context_length}")
        if props.get("total_slots") != 1:
            problems.append(f"{props.get('total_slots')} slots (the window would be split)")
        template_hash = sha256_text(props.get("chat_template", ""))
        if template_hash != pin.chat_template_sha256:
            problems.append("the chat template differs from the pin")
        # A default system prompt would be text the lab does not record (D-060): a bare user message must
        # render with no system block at all.
        if not bare.get("prompt", "").startswith(pin.user_turn_start):
            problems.append("the runtime injects text before the user turn (a default system prompt?)")
        if problems:
            raise ServerCheckError("the model server does not match the pin: " + "; ".join(problems))
        rendered_hash = sha256_text(prefix["prompt"])
        if pin.rendered_prefixes is not None:
            expected = pin.rendered_prefixes.get(sha256_text(system))
            if expected is None:
                raise ServerCheckError("no rendered prefix is pinned for this system prompt: re-pin after the prompt changed")
            if expected != rendered_hash:
                raise ServerCheckError("the rendered request prefix differs from the pin (the server was restarted with "
                                       "different flags, or its template changed)")
        self._window_selftest()
        self._facts = {"build_info": props["build_info"], "chat_template_sha256": template_hash,
                       "rendered_prefix_sha256": rendered_hash, "prefix_pinned": pin.rendered_prefixes is not None,
                       "process_verified": True}
        return {"rendered_prefix": prefix["prompt"], "weights_path": weights_path, **self._facts}

    def _window_selftest(self) -> None:
        """Send a prompt far over the window and require the server to REFUSE it, not truncate it. This tests the window and the
        refusal the client relies on (it maps that refusal to the context limit). It does NOT test context shift: that only acts
        when a reply grows past the window, a prompt over it is refused either way (checked live against this build,
        D-069); context shift is checked through the process's command line by check_process. One token to predict."""
        try:
            self._request("POST", "/completion", {"prompt": "x " * (2 * self.pin.context_length), "n_predict": 1, "stream": False})
        except urllib.error.HTTPError as err:
            if err.code == 400 and getattr(err, "detail", {}).get("type") == "exceed_context_size_error":
                return
            raise ServerCheckError(f"the over-window self-test got HTTP {err.code}, not the context-size refusal") from None
        except (urllib.error.URLError, OSError, ModelError) as err:
            raise ServerCheckError(f"the over-window self-test could not run: {err}") from None
        raise ServerCheckError("the server accepted a prompt far over its window: the window is not what the pin says, or the server "
                               "truncates over-long prompts, and the context limit could not be detected")

    @property
    def local_runtime(self) -> dict:
        """The manifest's local_runtime block (D-060). Fields the live server never confirmed are the zero
        hash, so a run that failed before the check still validates and is plainly marked."""
        pin = self.pin
        return {"runtime": pin.runtime, "runtime_version": pin.runtime_version, "weights_sha256": pin.weights_sha256,
                "quantization": pin.quantization, "context_length": pin.context_length, "seed": self.seed,
                "chat_template_sha256": self._facts.get("chat_template_sha256", ZERO_HASH),
                "rendered_prefix_sha256": self._facts.get("rendered_prefix_sha256", ZERO_HASH),
                "refusal_modified": pin.refusal_modified}

    # ---- one turn ----
    def converse(self, *, system: str, messages: list[dict], tool_config: dict, inference: dict) -> ModelReply:
        try:
            rendered = self._request("POST", "/apply-template", {
                "messages": to_openai_messages(system, messages), "tools": to_openai_tools(tool_config)})
            out = self._request("POST", "/completion", {
                "prompt": rendered["prompt"], "n_predict": inference["max_tokens"], "temperature": inference["temperature"],
                "top_p": inference["top_p"], "seed": self.seed, "stream": False, **self.pin.sampler})
        except urllib.error.HTTPError as err:
            detail = getattr(err, "detail", {})
            if err.code == 400 and detail.get("type") == "exceed_context_size_error":
                # The window is full and context shift is off, so the server refuses: that is the context limit.
                return ModelReply(content=[], stop_reason="model_context_window_exceeded",
                                  input_tokens=int(detail.get("n_prompt_tokens", 0)), output_tokens=0, request_id=None,
                                  raw_stop_reason="exceed_context_size_error")
            kind = REQUEST_REJECTED if err.code in (400, 401, 403, 404, 422) else SERVICE
            raise ModelError(f"HTTP {err.code} from the model server: {detail.get('message', '')[:200]}", kind=kind) from None
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as err:
            raise ModelError(f"{type(err).__name__}: {err}", kind=SERVICE) from None
        except KeyError as err:
            raise ModelError(f"the server's reply lacked {err}", kind=SERVICE) from None

        raw = out.get("content", "")
        stop_type = out.get("stop_type", "")

        def make_id() -> str:
            self._calls += 1
            return f"call_{self._calls}"

        content, stop_reason = TOOL_CALL_PARSERS[self.pin.tool_call_format](raw, stop_type, make_id)
        return ModelReply(content=content, stop_reason=stop_reason, input_tokens=int(out.get("tokens_evaluated", 0)),
                          output_tokens=int(out.get("tokens_predicted", 0)), request_id=None, retries=0,
                          raw_stop_reason=stop_type, raw_completion=raw)


def verify_weights(path: Path, expected_sha256: str, chunk: int = 8 * 1024 * 1024) -> None:
    """Hash the weights file and compare with the pin, every run: about ten seconds for 5 GB against a run of several
    minutes. (A stamp cache keyed on size and modification time was removed in D-069: anything able to write the
    file can also reset its modification time.)"""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while block := handle.read(chunk):
            digest.update(block)
    if "sha256:" + digest.hexdigest() != expected_sha256:
        raise ServerCheckError(f"{path.name} does not match the pinned SHA-256")
