"""Check the committed pin against the RUNNING local model server (D-068, D-069). Nothing is generated.

    powershell -NoProfile -File harness/local_server.ps1 start
    .venv/Scripts/python harness/local_check.py
    powershell -NoProfile -File harness/local_server.ps1 stop

This is exactly the check `run.py --backend local` makes at the start of every run, made on its own so it can be run and
read. For each condition it renders the REAL study prompt through the server's own template (the system text, the tools and
the opening message) and compares everything with harness/local_pin.json:

  * the server PROCESS: it listens on loopback only, its command line equals the pin's flags, it loaded the pinned weights;
  * the build, window, one slot, the chat template, and that nothing is injected before the user's turn;
  * the rendered prefix, against the hash pinned for that condition (so a restart with different flags, such as thinking mode
    switched on, is refused);
  * a prompt far over the window is refused;
  * the weights file the server loaded matches the pinned SHA-256 (about ten seconds);
  * a request without the API key is refused.

It only RENDERS the study prompt (`/apply-template`); it never asks the model to answer it. The first time the model answers
the study prompt is the floor check (D-060). Exit code 0 only if every check passes.
"""

from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "harness"))

from local_model import LocalClient, LocalPin, ServerCheckError, local_settings, verify_weights  # noqa: E402
from prompt_set import CONDITIONS, load_prompts  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default=None)
    parser.add_argument("--key-file", type=Path, default=None)
    parser.add_argument("--pin", type=Path, default=None)
    args = parser.parse_args(argv)
    url, key_file, pin_file = local_settings()
    url, key_file, pin_file = args.url or url, args.key_file or key_file, args.pin or pin_file
    if not key_file.is_file():
        print(f"no key file at {key_file}")
        return 1
    pin = LocalPin.from_file(pin_file) if pin_file else LocalPin.from_file()
    key = key_file.read_text().strip()
    prompts = load_prompts()
    failed = False
    weights_path = None

    for condition in CONDITIONS:
        client = LocalClient(url, key, pin, seed=1)
        try:
            facts = client.prepare(prompts.system_text(condition), prompts.tool_config, prompts.opening)
            weights_path = facts["weights_path"]
            print(f"PASS  {condition:<8} rendered prefix {facts['rendered_prefix_sha256'][:23]}... matches the pin; "
                  f"build {facts['build_info']}; process, flags, bind, window and template match")
        except ServerCheckError as err:
            failed = True
            print(f"FAIL  {condition:<8} {err}")

    if weights_path:
        try:
            verify_weights(Path(weights_path), pin.weights_sha256)
            print(f"PASS  weights  {Path(weights_path).name} matches the pinned SHA-256")
        except ServerCheckError as err:
            failed = True
            print(f"FAIL  weights  {err}")

    try:
        urllib.request.urlopen(urllib.request.Request(url + "/props"), timeout=10)
        failed = True
        print("FAIL  auth     /props answered without the API key")
    except urllib.error.HTTPError as err:
        print(f"{'PASS' if err.code == 401 else 'FAIL'}  auth     /props without the key answered {err.code} (expected 401)")
        failed = failed or err.code != 401
    except OSError as err:
        failed = True
        print(f"FAIL  auth     the server could not be reached: {err}")

    print("\nALL CHECKS PASSED" if not failed else "\nSOMETHING FAILED: do not start a run until it is fixed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
