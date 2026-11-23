"""Regenerate harness/local_pin.json's `rendered_prefixes` after a prompts/ change that doesn't touch the
server, the model, the sampler, or the system text itself (e.g. D-079's tools.json wording). Needs the live
pinned server. Every OTHER field of the pin (weights, build, window, template, sampler, server_flags) must
already match the running server, or LocalClient.prepare refuses before this gets to the render.

    python repin_rendered_prefixes.py <repo root>

Prints the old and new hash per condition, then overwrites harness/local_pin.json (only the
`rendered_prefixes` key; everything else in the file is preserved byte-for-byte otherwise).
"""
import dataclasses
import json
import sys
from pathlib import Path

ROOT = Path(sys.argv[1])
sys.path.insert(0, str(ROOT / "harness"))
from local_model import LocalClient, LocalPin, local_settings, sha256_text  # noqa: E402
from prompt_set import CONDITIONS, load_prompts  # noqa: E402

url, key_file, pin_file = local_settings()
pin_path = pin_file or (ROOT / "harness" / "local_pin.json")
pin = LocalPin.from_file(pin_path)
key = key_file.read_text().strip()
prompts = load_prompts()

# Skip the very rendered-prefix check this script exists to satisfy, so prepare() can render and report the
# NEW hash instead of refusing on the old one. Every other pin field is still checked against the live server.
unpinned = dataclasses.replace(pin, rendered_prefixes=None)

new_prefixes: dict[str, str] = {}
for condition in CONDITIONS:
    system = prompts.system_text(condition)
    facts = LocalClient(url, key, unpinned, seed=1).prepare(system, prompts.tool_config, prompts.opening)
    new_prefixes[sha256_text(system)] = facts["rendered_prefix_sha256"]
    print(f"{condition}: build {facts['build_info']}; process, flags, window and template still match the pin")

data = json.loads(pin_path.read_text(encoding="utf-8"))
old = data.get("rendered_prefixes")
print("\nold rendered_prefixes:", old)
print("new rendered_prefixes:", new_prefixes)
data["rendered_prefixes"] = new_prefixes
pin_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")
print(f"\nwrote {pin_path}")
