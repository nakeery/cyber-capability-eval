"""Turn the target's stdout into schema-ready events (D-041).

The target never knows run_id, so the harness adds it here. Used by the phase 2
tests and, unchanged, by the phase 4 log collection. Strict on purpose: any stdout
line that is not a JSON object is an error, because the only thing the target may
print on stdout is events.
"""

from __future__ import annotations

import json


def collect_events(stdout_text: str, run_id: str) -> list[dict]:
    events = []
    for number, line in enumerate(stdout_text.split("\n"), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            raise ValueError(f"target stdout line {number} is not JSON") from None
        if not isinstance(record, dict):
            raise ValueError(f"target stdout line {number} is not a JSON object")
        events.append({**record, "run_id": run_id})
    return events
