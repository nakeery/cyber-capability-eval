"""Find which strings the pinned local server turns into special tokens, and write `harness/special_tokens.json` (D-077).

    powershell -NoProfile -File harness/local_server.ps1 start
    .venv/Scripts/python harness/gguf_tokens.py extract
    powershell -NoProfile -File harness/local_server.ps1 stop

The neutralizer (`harness/special_tokens.py`) must know every string the server reads as a special token, and D-073
ruled that such a list is read from the tokenizer, never typed by hand. Two sources, both mechanical, both recorded:

  * "gguf": the weights' own metadata. Each token has a type, and llama.cpp matches the types unknown, control and
    user-defined inside text when it parses special tokens. Only the header is read, never the tensors.
  * "server": what the pinned runtime actually does, beyond the file. llama.cpp promotes some end-of-sequence-looking
    names to control tokens whatever the file says (in Qwen3's file `</s>` is an ordinary token, and the server parses it
    as special all the same: found by this sweep, D-077). A text is tokenized with special parsing on and with it off;
    a control or unknown token comes out differently, so the sweep narrows a list of every vocabulary string by halves
    until it is down to the strings that differ. (A user-defined token is matched in both modes and cannot show up this
    way. Those are the file's type 4, which the first source reads in full, with one caveat: llama.cpp is said to mark a
    few names as user-defined whatever the file says (from memory of its source, not checked against this build). None
    of those names is in this vocabulary, checked by name; a new pin needs that check again.)

The weights file is hashed against the pin first, and the server must report the pinned build and weights file, so the
list is only ever made from the pinned model. It is a separate module so that the list can be (re)written when none
exists yet: `special_tokens.py` refuses to load without one.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
import urllib.request
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
TOKENS_PATH = ROOT / "harness" / "special_tokens.json"
DEFAULT_WEIGHTS = Path("G:/model-eval-local/models/qwen3-8b-q4_k_m/Qwen3-8B-Q4_K_M.gguf")

# llama.cpp's token types (LLAMA_TOKEN_TYPE_*) that its tokenizer matches in text when it parses special tokens.
UNKNOWN, CONTROL, USER_DEFINED = 2, 3, 4
SPECIAL_TYPES = (UNKNOWN, CONTROL, USER_DEFINED)
ORIGINS = ("gguf", "server")
SWEEP_CHUNK = 4000          # vocabulary strings per request in the first round of the sweep

_GGUF_SCALARS = {0: "<B", 1: "<b", 2: "<H", 3: "<h", 4: "<I", 5: "<i", 6: "<f", 7: "<?", 10: "<Q", 11: "<q", 12: "<d"}
_GGUF_STRING, _GGUF_ARRAY = 8, 9
_WANTED_KEYS = ("tokenizer.ggml.model", "tokenizer.ggml.tokens", "tokenizer.ggml.token_type")


def _read(handle, fmt: str):
    size = struct.calcsize(fmt)
    data = handle.read(size)
    if len(data) != size:
        raise ValueError("the GGUF file ends in the middle of its metadata")
    return struct.unpack(fmt, data)[0]


def _read_string(handle) -> str:
    length = _read(handle, "<Q")
    data = handle.read(length)
    if len(data) != length:
        raise ValueError("the GGUF file ends in the middle of its metadata")
    return data.decode("utf-8", errors="replace")


def _skip_string(handle) -> None:
    handle.seek(_read(handle, "<Q"), 1)


def _read_value(handle, kind: int, keep: bool):
    """One metadata value. When `keep` is false the value is skipped (the merges list is as long as the vocabulary)."""
    if kind in _GGUF_SCALARS:
        return _read(handle, _GGUF_SCALARS[kind])
    if kind == _GGUF_STRING:
        if keep:
            return _read_string(handle)
        _skip_string(handle)
        return None
    if kind == _GGUF_ARRAY:
        element, count = _read(handle, "<I"), _read(handle, "<Q")
        if element == _GGUF_STRING:
            if keep:
                return [_read_string(handle) for _ in range(count)]
            for _ in range(count):
                _skip_string(handle)
            return None
        if element not in _GGUF_SCALARS:
            raise ValueError(f"a GGUF array of value type {element} is not one this reader knows")
        fmt = _GGUF_SCALARS[element]
        width = count * struct.calcsize(fmt)
        if keep:
            data = handle.read(width)
            if len(data) != width:
                raise ValueError("the GGUF file ends in the middle of its metadata")
            return list(struct.unpack(f"<{count}{fmt[1]}", data))
        handle.seek(width, 1)
        return None
    raise ValueError(f"a GGUF value of type {kind} is not one this reader knows")


def read_token_table(path: Path) -> dict:
    """{"tokenizer_model": str, "tokens": [str], "types": [int]} from a GGUF file's metadata (versions 2 and 3).

    Strict: anything the reader does not understand is an error, because a list built from half-read metadata would be
    a silent hole in the neutralizer."""
    found: dict = {}
    with open(path, "rb", buffering=1 << 20) as handle:
        if handle.read(4) != b"GGUF":
            raise ValueError(f"{Path(path).name} is not a GGUF file")
        version = _read(handle, "<I")
        if version not in (2, 3):
            raise ValueError(f"GGUF version {version} is not one this reader knows")
        _read(handle, "<Q")                 # tensor count
        pairs = _read(handle, "<Q")
        for _ in range(pairs):
            key = _read_string(handle)
            kind = _read(handle, "<I")
            value = _read_value(handle, kind, key in _WANTED_KEYS)
            if key in _WANTED_KEYS:
                found[key] = value
            if len(found) == len(_WANTED_KEYS):
                break
    missing = [key for key in _WANTED_KEYS if key not in found]
    if missing:
        raise ValueError(f"the GGUF metadata has no {', '.join(missing)}")
    tokens, types = found["tokenizer.ggml.tokens"], found["tokenizer.ggml.token_type"]
    if len(tokens) != len(types):
        raise ValueError(f"{len(tokens)} tokens but {len(types)} token types")
    return {"tokenizer_model": found["tokenizer.ggml.model"], "tokens": tokens, "types": types}


def special_entries(table: dict) -> list[dict]:
    """Every token of a type the runtime matches in text, in id order (origin "gguf")."""
    return [{"id": index, "text": text, "type": kind, "origin": "gguf"}
            for index, (text, kind) in enumerate(zip(table["tokens"], table["types"])) if kind in SPECIAL_TYPES]


def check_entries(entries: list[dict]) -> None:
    """Refuse a list the neutralizer cannot rely on. A neutralizer built from an empty or malformed list is a silent no-op."""
    if not entries:
        raise ValueError("the special-token list is empty: a neutralizer built from it would do nothing")
    ids = set()
    for entry in entries:
        text = entry.get("text")
        if not isinstance(text, str) or not text:
            raise ValueError(f"a special-token entry has no text: {entry!r}")
        if entry.get("origin") not in ORIGINS:
            raise ValueError(f"{text!r} has origin {entry.get('origin')!r}, not one of {ORIGINS}")
        if not isinstance(entry.get("type"), int) or isinstance(entry.get("type"), bool):
            raise ValueError(f"{text!r} has no token type")
        if entry["origin"] == "gguf" and entry["type"] not in SPECIAL_TYPES:
            raise ValueError(f"{text!r} has type {entry['type']}, not one the runtime matches in text")
        if not isinstance(entry.get("id"), int) or isinstance(entry.get("id"), bool) or entry["id"] in ids:
            raise ValueError(f"{text!r} has a missing or repeated id")
        ids.add(entry["id"])
        # A token with a newline could be built across the newlines the harness puts between the pieces it joins.
        if "\n" in text:
            raise ValueError(f"{text!r} holds a newline, which the harness's cuts and joins rely on no token having")


# --- what the running server does, beyond the file ------------------------------------------------------------------

Tokenize = Callable[[str, bool], list]      # (text, parse_special) -> token ids


def server_tokenize(url: str, key: str, text: str, parse_special: bool) -> list[int]:
    """The server's `/tokenize`, through the loopback-only opener (the key never goes through a proxy)."""
    sys.path.insert(0, str(ROOT / "harness"))
    from local_model import NO_PROXY_OPENER
    body = json.dumps({"content": text, "add_special": False, "parse_special": parse_special}).encode("utf-8")
    request = urllib.request.Request(url.rstrip("/") + "/tokenize", data=body, method="POST",
                                     headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"})
    with NO_PROXY_OPENER.open(request, timeout=120) as response:
        return json.loads(response.read())["tokens"]


def find_server_specials(table: dict, known_ids: set[int], tokenize: Tokenize, chunk: int = SWEEP_CHUNK) -> list[dict]:
    """Vocabulary strings outside `known_ids` that the server matches as special tokens (origin "server").

    A text made of vocabulary strings is tokenized with special parsing on and off. If the two differ, something in it
    is matched as special, so the text is halved and each half is tried again, down to single strings. A control or
    unknown token is matched only with parsing on, so only those show up; the user-defined ones are the file's own type 4
    (see the module text for the one caveat)."""
    items = [(index, text) for index, text in enumerate(table["tokens"]) if index not in known_ids]
    found: list[dict] = []

    def narrow(part: list[tuple[int, str]]) -> None:
        if not part:
            return
        joined = "\n".join(text for _, text in part)
        if tokenize(joined, True) == tokenize(joined, False):
            return
        if len(part) == 1:
            index, text = part[0]
            found.append({"id": index, "text": text, "type": table["types"][index], "origin": "server"})
            return
        middle = len(part) // 2
        narrow(part[:middle])
        narrow(part[middle:])

    for start in range(0, len(items), chunk):
        narrow(items[start:start + chunk])
    return found


def check_server_is_pinned(url: str, key: str, pin) -> str:
    """Refuse a server that is not the pinned build and weights file. Returns the build. (`local_check.py` is the
    full audit of the server; this is the part the sweep depends on.)"""
    sys.path.insert(0, str(ROOT / "harness"))
    from local_model import NO_PROXY_OPENER
    request = urllib.request.Request(url.rstrip("/") + "/props", headers={"Authorization": f"Bearer {key}"})
    with NO_PROXY_OPENER.open(request, timeout=30) as response:
        props = json.loads(response.read())
    reported = str(props.get("model_path", "")).replace("\\", "/").split("/")[-1]
    if props.get("build_info") != pin.runtime_version or reported != pin.weights_file:
        raise ValueError(f"the server reports build {props.get('build_info')!r} and weights {reported!r}, "
                         f"not the pinned {pin.runtime_version!r} and {pin.weights_file!r}")
    return props["build_info"]


def extract(weights: Path, out: Path) -> int:
    sys.path.insert(0, str(ROOT / "harness"))
    from local_model import LocalPin, local_settings, verify_weights
    pin = LocalPin.from_file()
    verify_weights(weights, pin.weights_sha256)            # the list is only as good as the file it was read from
    table = read_token_table(weights)
    entries = special_entries(table)
    check_entries(entries)
    url, key_file, _ = local_settings()
    key = key_file.read_text().strip()
    build = check_server_is_pinned(url, key, pin)
    extra = find_server_specials(table, {entry["id"] for entry in entries},
                                 lambda text, parse: server_tokenize(url, key, text, parse))
    entries = sorted(entries + extra, key=lambda entry: entry["id"])
    check_entries(entries)
    document = {"weights_sha256": pin.weights_sha256, "tokenizer_model": table["tokenizer_model"],
                "vocabulary_size": len(table["tokens"]), "types_included": list(SPECIAL_TYPES),
                "server_build": build, "tokens": entries}
    out.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {len(entries)} special tokens ({len(entries) - len(extra)} from the file's types, {len(extra)} found on "
          f"the server) of {len(table['tokens'])} to {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    sub = commands.add_parser("extract", help="rewrite harness/special_tokens.json from the pinned weights and server")
    sub.add_argument("--weights", type=Path, default=DEFAULT_WEIGHTS)
    sub.add_argument("--out", type=Path, default=TOKENS_PATH)
    args = parser.parse_args(argv)
    return extract(args.weights, args.out)


if __name__ == "__main__":
    raise SystemExit(main())
