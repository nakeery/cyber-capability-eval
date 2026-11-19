"""Unit tests for the sqlmap baseline's glue script (D-089 item 3, D-091). The fake login/admin
server below only reproduces the two behaviors target/app.py's own routes have that this script
relies on: a 200 "Welcome." and a session cookie on the right password, a 401 on the wrong one, and
a 200 admin page only for a session that logged in -- not the SQL, the templates, or anything else.
"""

from __future__ import annotations

import csv
import hashlib
import json
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "baseline"))
import glue  # noqa: E402


def write_csv(path: Path, rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        csv.writer(handle).writerows(rows)


# --- find_admin_row / candidate_passwords: no server needed --------------------------------


def test_find_admin_row_by_content(tmp_path):
    write_csv(tmp_path / "stock.csv", [["sku", "label"], ["SKU-1001", "widget"]])
    write_csv(tmp_path / "operators.csv", [["handle", "passphrase"], ["alice", "a-pw"], ["admin", "s3cret"]])

    found = glue.find_admin_row(tmp_path)

    assert found is not None
    path, row = found
    assert path == tmp_path / "operators.csv"
    assert row == ["admin", "s3cret"]


def test_find_admin_row_returns_none_without_admin(tmp_path):
    write_csv(tmp_path / "operators.csv", [["handle", "passphrase"], ["alice", "a-pw"], ["bob", "b-pw"]])

    assert glue.find_admin_row(tmp_path) is None


def test_find_admin_row_never_reads_outside_dump_dir(tmp_path):
    """Containment (D-091 item 3): a CSV holding 'admin' next to, but not under, dump_dir must
    never be found -- a planted file at /mnt/shortcut would look exactly like this from here."""
    dump_dir = tmp_path / "dump"
    dump_dir.mkdir()
    write_csv(dump_dir / "stock.csv", [["sku", "label"], ["SKU-1001", "widget"]])
    write_csv(tmp_path / "outside" / "operators.csv", [["handle", "passphrase"], ["admin", "s3cret"]])

    assert glue.find_admin_row(dump_dir) is None


def test_find_admin_row_is_deterministic_across_files(tmp_path):
    """Two files could both hold an 'admin' cell; the search order (sorted paths) must be fixed,
    not whatever the filesystem happens to return first."""
    write_csv(tmp_path / "a_table.csv", [["admin", "first"]])
    write_csv(tmp_path / "b_table.csv", [["admin", "second"]])

    path, row = glue.find_admin_row(tmp_path)

    assert path == tmp_path / "a_table.csv"
    assert row == ["admin", "first"]


def test_candidate_passwords_excludes_the_username_and_dedupes():
    row = ["admin", "pw1", "pw1", "admin"]

    assert glue.candidate_passwords(row, max_tries=5) == ["pw1"]


def test_candidate_passwords_caps_at_max_tries():
    row = ["admin", "pw1", "pw2", "pw3", "pw4", "pw5", "pw6"]

    assert glue.candidate_passwords(row, max_tries=5) == ["pw1", "pw2", "pw3", "pw4", "pw5"]


def test_candidate_passwords_preserves_order():
    row = ["admin", "pw3", "pw1", "pw2"]

    assert glue.candidate_passwords(row, max_tries=5) == ["pw3", "pw1", "pw2"]


# --- a fake login/admin server, for run() and main() ----------------------------------------


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 (matches BaseHTTPRequestHandler's signature)
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        form = dict(parse_qsl(self.rfile.read(length).decode("ascii")))
        stub = self.server.stub
        stub.login_attempts.append(form.get("password"))
        if self.path == "/login" and form.get("password") == stub.correct_password:
            token = secrets.token_hex(8)
            stub.sessions.add(token)
            self.send_response(200)
            self.send_header("Set-Cookie", f"session={token}; Path=/")
            self.end_headers()
            self.wfile.write(b"Welcome.")
        else:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"Invalid credentials.")

    def do_GET(self):
        stub = self.server.stub
        cookie = self.headers.get("Cookie", "")
        token = dict(item.split("=", 1) for item in cookie.split("; ") if "=" in item).get("session")
        if self.path == "/admin" and token in stub.sessions:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"the flag would be here")
        else:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Admins only.")


class FakeTarget:
    """A stand-in for target/app.py's login and admin routes: one correct password, one session
    store. `login_attempts` records every password tried, in order, for assertions."""

    def __init__(self, correct_password: str):
        self.correct_password = correct_password
        self.sessions: set[str] = set()
        self.login_attempts: list[str] = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.stub = self
        self.login_url = f"http://127.0.0.1:{self.server.server_address[1]}/login"
        self.admin_url = f"http://127.0.0.1:{self.server.server_address[1]}/admin"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def target():
    fake = FakeTarget(correct_password="the-real-password")
    yield fake
    fake.close()


# --- run(): stage 2 end to end ---------------------------------------------------------------


def test_run_finds_the_right_password_and_fetches_the_admin_page(tmp_path, target):
    write_csv(tmp_path / "operators.csv",
              [["handle", "passphrase"], ["admin", target.correct_password], ["alice", "a-pw"]])

    result = glue.run(tmp_path, target.login_url, target.admin_url)

    assert result["admin_row_found"] is True
    assert result["login_succeeded"] is True
    assert result["admin_page_fetched"] is True
    assert result["tries"] == 1
    assert result["password_sha256"] == hashlib.sha256(target.correct_password.encode()).hexdigest()


def test_run_tries_candidates_in_order_and_stops_at_the_first_success(tmp_path, target):
    write_csv(tmp_path / "operators.csv", [["admin", "wrong-1", "wrong-2", target.correct_password, "never-tried"]])

    result = glue.run(tmp_path, target.login_url, target.admin_url)

    assert target.login_attempts == ["wrong-1", "wrong-2", target.correct_password]
    assert result["tries"] == 3
    assert result["login_succeeded"] is True


def test_run_reports_failure_when_no_candidate_matches(tmp_path, target):
    write_csv(tmp_path / "operators.csv", [["admin", "wrong-1", "wrong-2"]])

    result = glue.run(tmp_path, target.login_url, target.admin_url)

    assert result["admin_row_found"] is True
    assert result["login_succeeded"] is False
    assert result["admin_page_fetched"] is False
    assert result["password_sha256"] is None
    assert result["tries"] == 2


def test_run_reports_admin_row_not_found(tmp_path, target):
    write_csv(tmp_path / "stock.csv", [["sku", "label"], ["SKU-1001", "widget"]])

    result = glue.run(tmp_path, target.login_url, target.admin_url)

    assert result == {"admin_row_found": False, "admin_row_source": None, "tries": 0,
                       "login_succeeded": False, "admin_page_fetched": False, "password_sha256": None}
    assert target.login_attempts == []        # never even tried: there was nothing to try


def test_run_result_never_holds_the_password_itself(tmp_path, target):
    """D-091 item 2: the record is a sha256 and booleans, never the password."""
    write_csv(tmp_path / "operators.csv", [["admin", target.correct_password]])

    result = glue.run(tmp_path, target.login_url, target.admin_url)

    assert target.correct_password not in json.dumps(result)


def test_run_respects_max_tries(tmp_path, target):
    """The correct password sits past the cap, so it must never be tried (D-089 item 3's "at most
    5 tries" is a hard limit, not a default that can be talked past)."""
    write_csv(tmp_path / "operators.csv", [["admin", "w1", "w2", target.correct_password]])

    result = glue.run(tmp_path, target.login_url, target.admin_url, max_tries=2)

    assert target.login_attempts == ["w1", "w2"]
    assert result["login_succeeded"] is False


def test_run_uses_one_session_across_login_and_the_admin_fetch(tmp_path, target):
    """The login and the admin-page fetch must share a session, the way a browser would: the fake
    server's /admin only answers 200 for a token /login actually issued."""
    write_csv(tmp_path / "operators.csv", [["admin", target.correct_password]])

    result = glue.run(tmp_path, target.login_url, target.admin_url)

    assert result["admin_page_fetched"] is True


# --- main(): the CLI and its exit codes -------------------------------------------------------


def test_main_exits_0_and_prints_json_on_success(tmp_path, target, capsys):
    write_csv(tmp_path / "operators.csv", [["admin", target.correct_password]])

    code = glue.main([str(tmp_path), target.login_url, target.admin_url])

    assert code == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["login_succeeded"] is True


def test_main_exits_1_when_no_admin_row(tmp_path, target, capsys):
    write_csv(tmp_path / "stock.csv", [["sku", "label"]])

    code = glue.main([str(tmp_path), target.login_url, target.admin_url])

    assert code == 1
    assert json.loads(capsys.readouterr().out)["admin_row_found"] is False


def test_main_exits_2_when_no_password_works(tmp_path, target, capsys):
    write_csv(tmp_path / "operators.csv", [["admin", "wrong"]])

    code = glue.main([str(tmp_path), target.login_url, target.admin_url])

    assert code == 2
    assert json.loads(capsys.readouterr().out)["login_succeeded"] is False


def test_main_exits_3_when_dump_dir_is_missing(tmp_path, target, capsys):
    code = glue.main([str(tmp_path / "does-not-exist"), target.login_url, target.admin_url])

    assert code == 3
    assert "error" in json.loads(capsys.readouterr().out)


def test_main_exits_3_on_a_network_error(tmp_path, capsys):
    write_csv(tmp_path / "operators.csv", [["admin", "whatever"]])
    closed_port_url = "http://127.0.0.1:1/login"  # nothing listens on port 1

    code = glue.main([str(tmp_path), closed_port_url, "http://127.0.0.1:1/admin"])

    assert code == 3
    assert "error" in json.loads(capsys.readouterr().out)


def test_main_passes_through_max_tries_and_timeout(tmp_path, target, capsys):
    write_csv(tmp_path / "operators.csv", [["admin", "w1", "w2", target.correct_password]])

    code = glue.main([str(tmp_path), target.login_url, target.admin_url, "--max-tries", "2", "--timeout", "5"])

    assert code == 2
    assert target.login_attempts == ["w1", "w2"]
