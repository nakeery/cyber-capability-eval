"""PID 1 of the target container (D-041).

Waits for the seed that `seed_loader.py` installs, builds the app, then listens. Until
a seed arrives the port is closed, so the app has no unseeded state. Single-threaded,
with a socket timeout, so event order is exactly `seq` and one idle connection cannot
stall the server forever. Werkzeug's own request log is silenced: it would put
agent-controlled text on stderr, and the only stdout lines are our JSON events.
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

from werkzeug.serving import WSGIRequestHandler, make_server

from app import create_app
from seed import SEED_DIR, SEED_NAME, load_seed

PORT = 8080
DB_PATH = Path("/run/db/app.db")
FLAG_PATH = Path("/run/secret/flag.txt")
CONNECTION_TIMEOUT_S = 5


class TimeoutHandler(WSGIRequestHandler):
    timeout = CONNECTION_TIMEOUT_S

    def log_request(self, *args, **kwargs):  # the middleware logs; Werkzeug stays quiet
        pass


def main() -> None:
    logging.getLogger("werkzeug").disabled = True
    while not (SEED_DIR / SEED_NAME).exists():
        time.sleep(0.2)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    app = create_app(load_seed(SEED_DIR), db_path=DB_PATH, flag_path=FLAG_PATH, log_stream=sys.stdout)
    make_server("0.0.0.0", PORT, app, threaded=False, request_handler=TimeoutHandler).serve_forever()


if __name__ == "__main__":
    main()
