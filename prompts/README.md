# prompts/

Everything the harness writes into the model's context, committed as plain text (D-061 to D-063). The agent's own text and the target's responses are not here; everything else it can see is. These files freeze at pre-registration, and a change after that needs a superseding entry that names the pilot observation behind it (a refusal is never one, D-060).

| File | What it is |
|---|---|
| `system.md` | The task prompt. `{TARGET_URL}` is the only placeholder. |
| `hint.txt` | The B + hint text (D-015's statement, widened by D-080 and D-085), appended to the system text in that condition only. |
| `opening.txt` | The fixed first user message (Converse needs a first user turn). |
| `tools.json` | The two tools, in the Converse `toolConfig.tools` shape. Nova accepts only `type`, `properties` and `required` in an input schema, so strictness (D-063) is enforced by the harness, not the schema. |
| `messages.json` | Every fixed text the harness itself shows the model: the `submit_flag` reply (D-001), the truncation marker and timeout notice (D-062), the empty-output notice (D-065: a command that prints nothing is shown as this line, never as an empty tool result, so the model is never handed a blank block), and one error per malformed-turn cause (D-063). |

## How the system text is assembled

- **System text** = the UTF-8 bytes of `system.md`, with `{TARGET_URL}` replaced by `http://target:8080`. No stripping, no other substitution. `system.md` has no trailing newline (D-085).
- **B + hint** = the system text, then one `\n`, then the bytes of `hint.txt`. The result has a blank line before the hint. Nothing else differs between the conditions.
- **`system_prompt_hash`** in the manifest = `sha256:` plus the SHA-256 of that exact text (hint included when present), so it differs by condition and the validator can recompute it. `hint_text` in the manifest is the contents of `hint.txt`, or `null`.
- `system.md`, `hint.txt` and `opening.txt` have no trailing newline, so what is hashed or compared is exactly what is sent.

## What the leak invariant scans

Every file here, as rendered into a request, for the run's flag, admin password and run ID (PLAN.md phase 4). For a local model the scan covers the request as the runtime renders it (D-060).

`tests/test_prompts.py` pins the invariants that must not drift: the base prompt never names the vulnerability or where the flag is held, the hint opens with the vulnerability statement and is one line (its exact text is not pinned while it is tuned, D-085), no file contains a secret-shaped token, and the `submit_flag` reply says nothing about correctness.
