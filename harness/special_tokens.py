"""Special-token text in what the model is shown and in what it writes (D-073 R2(a), D-077).

The local server tokenizes the rendered prompt with special-token parsing ON, so the TEXT `<|im_end|>` inside a tool
result becomes the one token the chat template uses to end a turn (D-073 measured it: a forged result added exactly the
extra start and end ids). This module owns what is done about it:

  * `harness/special_tokens.json` is the list of strings that count, read from the pinned weights' own token table by
    `harness/gguf_tokens.py extract` and never typed by hand. A test checks it against the pin, and against the weights
    file and the running server when they are there. This module refuses to load without it.
  * `neutralize` breaks every occurrence in a text by putting one space after its first character. The model still
    reads `< |im_end|>`; the server no longer sees a token. It INSERTS and never deletes: deleting `<|im_end|>` from
    `<|im_<|im_end|>end|>` would build a new marker out of the text around it.
  * `scan_step` and `scan_steps` find the strings again in the record. That covers the route `neutralize` does not:
    the model's own text and commands, which are re-rendered into every later prompt (D-073, reasoned and not probed).

A different model is a different list (and a different pin), never an edit to this code.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from gguf_tokens import TOKENS_PATH, check_entries

# Put after the first character of every occurrence. A plain space: visible in `output_sent_to_model`, untouched by
# sanitize (neutralizing is its last step), and in no token's text (checked when the list is loaded).
SEPARATOR = " "


def load_list(path: Path = TOKENS_PATH) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    check_entries(data["tokens"])
    for entry in data["tokens"]:
        if SEPARATOR in entry["text"]:
            raise ValueError(f"{entry['text']!r} holds the separator, so an insertion could be part of a match")
    return data


def _compile(texts) -> re.Pattern:
    """A zero-width lookahead, so every START of an occurrence is found, overlapping ones included. (Nothing in Qwen's
    list can overlap another, since each text has one `<`; another model's might, so this does not rely on it.)
    Longest first, so that group 1 names the longest token at a position."""
    return re.compile("(?=(" + "|".join(re.escape(text) for text in sorted(set(texts), key=len, reverse=True)) + "))")


_DATA = load_list()
SPECIAL_TEXTS = tuple(sorted({entry["text"] for entry in _DATA["tokens"]}))
_OCCURS = _compile(SPECIAL_TEXTS)


def check_list_matches_pin(weights_sha256: str, runtime_version: str) -> None:
    """The list belongs to one model's weights AND one runtime build: the weights say which strings are special, and
    the build decides which others it promotes (`</s>` here). A different pin with this list would neutralize the wrong
    strings without any error, so a run refuses to start on it ("a different model is a new list", module text)."""
    if _DATA["weights_sha256"] != weights_sha256 or _DATA["server_build"] != runtime_version:
        raise ValueError("harness/special_tokens.json was read from other weights or another runtime build than the pin's: "
                         "with the server running, run `.venv/Scripts/python harness/gguf_tokens.py extract` (D-077)")


def occurrences(text: str, pattern: re.Pattern = _OCCURS) -> list[tuple[int, str]]:
    """(start, token text) for every special-token string in `text`, overlapping ones included."""
    return [(match.start(), match.group(1)) for match in pattern.finditer(text)]


def find(text: str) -> list[str]:
    """The distinct special-token strings in `text`, in order of first appearance."""
    seen: list[str] = []
    for _, token in occurrences(text):
        if token not in seen:
            seen.append(token)
    return seen


def neutralize(text: str, pattern: re.Pattern = _OCCURS) -> str:
    """`text` with a space after the first character of every special-token string, so none is left.

    Why that is enough: the separator is in no token, so a match cannot include one. Every occurrence in the input
    gets a separator inside it, so none survives; and what is left between separators is a piece of the input, so a
    new occurrence would have been an old one. Deleting instead of inserting has no such argument (module text).
    `pattern` is the list's compiled form; the default is the committed list, and a test passes a made-up one."""
    starts = [start for start, _ in occurrences(text, pattern)]
    if not starts:
        return text
    pieces, done = [], 0
    for start in starts:
        pieces += [text[done:start + 1], SEPARATOR]
        done = start + 1
    pieces.append(text[done:])
    return "".join(pieces)


# --- the detector: the same strings, found again in the record -------------------------------------------------------

def _strings(value):
    """Every string in a JSON-like value (keys too), so a command and a submitted flag are both read."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(key)
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _found_in(*values) -> list[str]:
    out: list[str] = []
    for value in values:
        for text in _strings(value):
            for token in find(text):
                if token not in out:
                    out.append(token)
    return out


# The pinned call format's own tags (`qwen_xml_json`, local_model.TOOL_CALL). The parser keeps a malformed or cut-off
# call's WHOLE raw text as the turn's text, so they appear in `assistant_text` whenever a call is malformed. Re-rendering
# them puts back the tokens the model itself generated: not a forged boundary, and not what `model_wrote` is for.
CALL_FORMAT_TAGS = ("<tool_call>", "</tool_call>")


def scan_step(step: dict) -> dict[str, list[str]]:
    """The special-token strings in one recorded step, by what they mean:

      neutralized  in `output_full`: the command's own output held them, and the model was shown the neutralized form
                   (or, for a long output, perhaps none of it): the route D-077 closes. A floor, not a count: markers
                   split by a control character, and any beyond the 1 MiB the record stores, are not seen.
      leaked       in `output_sent_to_model`: the model was shown them. Never expected; it means neutralization did not
                   apply, or a harness-authored text holds one. A defect either way.
      call_format  the pinned call format's own tags (`CALL_FORMAT_TAGS`) in `assistant_text`: a malformed or cut-off
                   call, kept whole as text. Expected; counted so it is not mistaken for the next kind.
      model_wrote  any other string in `assistant_text`, and any in `tool_input` or `raw_tool_use` (a call tag inside a
                   command is the model putting a tag into its arguments): the model's own words, re-rendered into every
                   later prompt and NOT neutralized (D-077 detects this route, it does not close it).
    """
    in_text = _found_in(step.get("assistant_text"))
    elsewhere = _found_in(step.get("tool_input"), step.get("raw_tool_use"))
    model_wrote = [token for token in in_text if token not in CALL_FORMAT_TAGS]
    model_wrote += [token for token in elsewhere if token not in model_wrote]
    return {
        "neutralized": _found_in(step.get("output_full")),
        "leaked": _found_in(step.get("output_sent_to_model")),
        "call_format": [token for token in in_text if token in CALL_FORMAT_TAGS],
        "model_wrote": model_wrote,
    }


def scan_steps(steps: list[dict]) -> dict[str, list[int]]:
    """The step numbers in which each kind of special-token text appears."""
    out: dict[str, list[int]] = {"neutralized": [], "leaked": [], "call_format": [], "model_wrote": []}
    for step in steps:
        for kind, found in scan_step(step).items():
            if found:
                out[kind].append(step.get("step"))
    return out


def report_lines(steps: list[dict]) -> list[str]:
    """What a run's summary says about special-token text. Step numbers only: no agent text, no tool output."""
    found = scan_steps(steps)
    lines = []
    if found["model_wrote"]:
        lines.append(f"  WARNING: the model's own text or commands held special-token text in step(s) {found['model_wrote']}: "
                     "re-rendered into later prompts as real markers, not neutralized (D-077)")
    if found["leaked"]:
        lines.append(f"  WARNING: special-token text reached the model in step(s) {found['leaked']}: neutralization did not "
                     "apply (D-077)")
    if found["neutralized"]:
        lines.append(f"  note: special-token text in the output of step(s) {found['neutralized']} was neutralized (D-077)")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="List the steps of run directories that hold special-token text.")
    parser.add_argument("run_dirs", nargs="+", type=Path)
    worst = 0
    for run_dir in parser.parse_args(argv).run_dirs:
        steps = [json.loads(line) for line in (run_dir / "steps.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        found = scan_steps(steps)
        print(f"{run_dir.name}: " + ", ".join(f"{kind} {found[kind] or '-'}" for kind in ("neutralized", "leaked", "call_format", "model_wrote")))
        worst = max(worst, 1 if found["leaked"] or found["model_wrote"] else 0)
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
