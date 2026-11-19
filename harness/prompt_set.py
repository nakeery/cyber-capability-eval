"""Load the committed prompts and assemble exactly what the model is shown (D-061 to D-063).

The rules are in prompts/README.md. Everything here is a pure function of the committed files,
so the manifest's `system_prompt_hash` can be recomputed by anyone from the repository.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROMPTS_DIR = ROOT / "prompts"

# The attacker reaches the target by its compose service name (D-034), the same in every variant.
TARGET_URL = "http://target:8080"
PLACEHOLDER = "{TARGET_URL}"
CONDITIONS = ("no_hint", "hint")


def _read(name: str, directory: Path) -> str:
    # Bytes, then decode: no newline translation, so what is hashed is what is sent.
    return (directory / name).read_bytes().decode("utf-8")


@dataclass(frozen=True)
class Prompts:
    system_template: str
    hint: str
    opening: str
    tool_config: dict   # {"tools": [...]} in the Converse toolConfig shape
    messages: dict      # prompts/messages.json

    def hint_text(self, condition: str) -> str | None:
        """The manifest's `hint_text`: the hint's contents in the hint condition, otherwise null."""
        _check_condition(condition)
        return self.hint if condition == "hint" else None

    def system_text(self, condition: str, target_url: str = TARGET_URL) -> str:
        """The system text: the template with the URL filled in; in the hint condition, then one
        newline and the hint. Nothing else differs between the conditions."""
        _check_condition(condition)
        text = self.system_template.replace(PLACEHOLDER, target_url)
        return text + "\n" + self.hint if condition == "hint" else text

    def system_prompt_hash(self, condition: str, target_url: str = TARGET_URL) -> str:
        digest = hashlib.sha256(self.system_text(condition, target_url).encode("utf-8")).hexdigest()
        return f"sha256:{digest}"

    @property
    def tools(self) -> list[dict]:
        return self.tool_config["tools"]

    @property
    def submit_reply(self) -> str:
        return self.messages["submit_flag_reply"]

    @property
    def truncation_marker(self) -> str:
        return self.messages["truncation_marker"]

    @property
    def timeout_notice(self) -> str:
        return self.messages["timeout_notice"]

    @property
    def empty_output_notice(self) -> str:
        return self.messages["empty_output_notice"]

    @property
    def continue_nudge(self) -> str:
        """D-083: sent instead of ending the run on a text-only turn; the turn that makes `Limits.text_only_limit`
        consecutive text-only turns ends the run instead (so at most limit - 1 nudges in a row, D-084)."""
        return self.messages["continue_nudge"]

    def error_text(self, cause: str) -> str:
        return self.messages["errors"][cause]

    def harness_authored_texts(self, condition: str) -> list[str]:
        """Everything the harness itself puts into the model's context (D-061): the leak
        invariant scans each of these for the run's secrets before every model call."""
        return [
            self.system_text(condition),
            self.opening,
            json.dumps(self.tool_config, sort_keys=True),
            self.submit_reply,
            self.truncation_marker,
            self.timeout_notice,
            self.empty_output_notice,
            self.continue_nudge,
            *self.messages["errors"].values(),
        ]


def _check_condition(condition: str) -> None:
    if condition not in CONDITIONS:
        raise ValueError(f"unknown condition {condition!r}")


def load_prompts(directory: Path = PROMPTS_DIR) -> Prompts:
    return Prompts(
        system_template=_read("system.md", directory),
        hint=_read("hint.txt", directory),
        opening=_read("opening.txt", directory),
        tool_config=json.loads(_read("tools.json", directory)),
        messages=json.loads(_read("messages.json", directory)),
    )


def find_leaks(texts: list[str], secrets: dict[str, str]) -> list[str]:
    """Names of the secrets that appear in any of the texts (empty if none).

    A plain substring test, so a secret split across two texts is not found; the harness-authored
    texts are fixed files, and a split secret would need an author who typed half of one."""
    return sorted(name for name, value in secrets.items() if value and any(value in text for text in texts))
