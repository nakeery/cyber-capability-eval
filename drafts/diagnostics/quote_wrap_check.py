"""Does wrapping the token that holds the stray apostrophe in double quotes fix the bash parse? A static text
transform plus `bash -n`, nothing is executed and nothing is sent anywhere. Prints lengths, a position and a
verdict only, never the command text.

    BASH_EXE=<path to bash.exe> python quote_wrap_test.py <repo root> <run id> <step>
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(sys.argv[1])
RUN = ROOT / "runs" / sys.argv[2]
K = int(sys.argv[3])
BASH = os.environ["BASH_EXE"]

steps = [json.loads(line) for line in (RUN / "steps.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
cmd = steps[K - 1]["tool_input"]["command"]


def bash_n(text: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, encoding="utf-8", newline="\n") as f:
        f.write(text)
        path = f.name
    try:
        done = subprocess.run([BASH, "-n", path], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20)
    finally:
        os.unlink(path)
    if done.returncode == 0:
        return "parses"
    return "UNBALANCED QUOTE" if "unexpected EOF while looking for matching" in done.stderr else "other syntax error"


print(f"recorded command: {len(cmd)} chars, {cmd.count(chr(39))} single quote(s), {cmd.count(chr(34))} double quote(s)")
print("baseline bash -n verdict:", bash_n(cmd))

if cmd.count("'") != 1 or '"' in cmd:
    print("this command isn't the simple 'exactly one unquoted apostrophe' shape; stopping (no transform applied).")
    sys.exit(0)

# The one apostrophe sits in some unquoted shell word (whitespace-delimited). Wrap exactly that word in double
# quotes, escaping the characters that are special inside double quotes (none of which show up in the counts
# already printed for this command, so this is the plain case).
idx = cmd.index("'")
start = cmd.rfind(" ", 0, idx) + 1
end = cmd.find(" ", idx)
if end == -1:
    end = len(cmd)
token = cmd[start:end]
escaped = token.replace("\\", "\\\\").replace("$", "\\$").replace("`", "\\`").replace('"', '\\"')
variant = cmd[:start] + '"' + escaped + '"' + cmd[end:]

print(f"the apostrophe sits in a word {len(token)} chars long, at position {start}-{end} of {len(cmd)}")
print(f"double-quote-wrapped variant: {len(variant)} chars")
print("variant bash -n verdict:", bash_n(variant))
