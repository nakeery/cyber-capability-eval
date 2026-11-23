"""Quick smoke test: send one benign prompt through PyRIT to the pinned local Qwen server (D-067), via
PyRIT's own OpenAIChatTarget against llama-server's OpenAI-compatible endpoint (--jinja enables
/v1/chat/completions; harness/local_model.py instead talks to the server's native /completion endpoint
directly, so this is a different, PyRIT-native path to the same server).

Not part of the harness, not study data, not the lab: this only reaches the model server, never Docker or
the target app. Exploratory, toward PLAN.md's phase 4b (PyRIT integration, not yet built). Prints the
result's outcome and the model's reply text.

    .venv/Scripts/python drafts/pyrit_quick_test.py ["your prompt here"]

PyRIT version this was written against: 1.2.1, pinned in requirements-pyrit.txt (NOT requirements.txt:
pyrit 1.2.1 requires jsonschema>=4.25.1, which conflicts with this project's jsonschema==4.23.0 pin and
breaks four real-Docker tests if installed into the same environment unpinned afterward -- see
requirements.txt's comment on this file). Re-pin jsonschema==4.23.0 after installing it if you installed
into the main .venv; this script has been checked and still works under that version.
"""
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "harness"))
from local_model import local_settings  # noqa: E402

from pyrit.executor.attack import PromptSendingAttack  # noqa: E402
from pyrit.prompt_target import OpenAIChatTarget  # noqa: E402
from pyrit.setup import initialize_pyrit_async  # noqa: E402


def _reply_text(reply) -> str:
    """Best-effort extraction across PyRIT response shapes; falls back to the raw repr."""
    for attr in ("converted_value", "original_value"):
        value = getattr(reply, attr, None)
        if isinstance(value, str) and value:
            return value
    pieces = getattr(reply, "message_pieces", None)
    if pieces:
        return _reply_text(pieces[0])
    return repr(reply)


async def main() -> None:
    prompt = sys.argv[1] if len(sys.argv) > 1 else "Say hello in exactly five words."
    url, key_file, _ = local_settings()
    if not key_file.is_file():
        print(f"no key file at {key_file} (start the server: harness/local_server.ps1 start)")
        return
    key = key_file.read_text().strip()

    # PyRIT's own run log (separate from this project's runs/); in-memory, nothing written to disk.
    await initialize_pyrit_async("InMemory")

    target = OpenAIChatTarget(
        endpoint=f"{url}/v1",   # the OpenAI SDK appends /chat/completions itself; a full URL 404s
        api_key=key,
        model_name="qwen3-8b",  # the server serves one model; this name is not checked
    )
    attack = PromptSendingAttack(objective_target=target)

    result = await attack.execute_async(objective=prompt)
    print("outcome:", result.outcome, "-", result.outcome_reason)
    print("conversation_id:", result.conversation_id)
    if result.error_message:
        print("error:", result.error_message)
    print("\nmodel's reply:\n", _reply_text(result.last_response))


if __name__ == "__main__":
    asyncio.run(main())
