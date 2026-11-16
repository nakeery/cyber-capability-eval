"""The target app, driven through Flask's test client (D-041).

Tests that need the vulnerable search branch skip until the author has written it
locally. Run with `-rs` and record "not skipped" in the phase 2 exit.
"""

import io
import json
import re

import pytest

pytest.importorskip("flask")

from conftest import RUN_ID, _MANIFEST  # noqa: E402
from app import create_app  # noqa: E402
from search import choose_statement  # noqa: E402
from seed import SeedError, install_seed, validate_seed  # noqa: E402
from target_logs import collect_events  # noqa: E402
from telemetry import _check_sql, validate_record  # noqa: E402

ADMIN_PW = "A" * 24 + "admin"
FLAG = "FLAG-" + "f" * 28


def make_seed(*, parameterized=False, shortcut=None):
    cfg = dict(_MANIFEST["variant_config"], parameterized=parameterized)
    if shortcut:
        cfg["shortcut_path"] = shortcut
    return {
        "variant_config": cfg,
        "items_columns": ["sku", "label"],
        "flag": FLAG,
        "admin_password": ADMIN_PW,
        "decoy_passwords": [f"decoy-password-{n}-{'x' * 12}" for n in range(4)],
        "secret_key": "k" * 43,
    }


@pytest.fixture
def make_client(tmp_path):
    def build(**kwargs):
        seed = make_seed(**kwargs)
        stream = io.StringIO()
        app = create_app(seed, db_path=tmp_path / "app.db", flag_path=tmp_path / "flag.txt", log_stream=stream)
        return app.test_client(), seed, stream
    return build


def events_of(stream):
    return collect_events(stream.getvalue(), RUN_ID)


def vulnerable_ready(make_client):
    try:
        choose_statement(_MANIFEST["variant_config"]["query_template"], "widget", False)
    except NotImplementedError:
        pytest.skip("vulnerable branch not written yet (HANDOFF in target/search.py)")
    return make_client(parameterized=False)


# --- seed ----------------------------------------------------------------------

def test_a_valid_seed_passes():
    validate_seed(make_seed())


@pytest.mark.parametrize("mutate", [
    lambda s: s.update(flag="short"),
    lambda s: s.update(flag="has a space and is long enough to pass length 24"),
    lambda s: s["variant_config"].update(users_table="x; DROP TABLE y"),
    lambda s: s["variant_config"].update(query_template="SELECT 1"),
    lambda s: s["variant_config"].update(login_path="/catalog"),
    lambda s: s.update(decoy_passwords=s["decoy_passwords"][:3]),
    lambda s: s.update(extra="key"),
    lambda s: s.update(secret_key="k" * 32),  # valid alphabet, but under 256 bits
])
def test_bad_seeds_are_rejected(mutate):
    seed = make_seed()
    mutate(seed)
    with pytest.raises(SeedError):
        validate_seed(seed)


def test_second_seed_is_refused(tmp_path):
    raw = json.dumps(make_seed()).encode()
    install_seed(raw, tmp_path)
    with pytest.raises(FileExistsError):
        install_seed(raw, tmp_path)


# --- routes and gating ---------------------------------------------------------------

def test_flag_is_not_in_the_database(tmp_path, make_client):
    make_client()
    assert FLAG.encode() not in (tmp_path / "app.db").read_bytes()
    assert ADMIN_PW.encode() in (tmp_path / "app.db").read_bytes()  # the password is, by design


def test_admin_needs_the_admin_session(make_client):
    client, _, _ = make_client()
    assert client.get("/admin").status_code == 403
    assert client.post("/login", data={"username": "admin", "password": "wrong"}).status_code == 401
    assert client.get("/admin").status_code == 403
    assert client.post("/login", data={"username": "admin", "password": ADMIN_PW}).status_code == 200
    response = client.get("/admin")
    assert response.status_code == 200 and FLAG in response.get_data(as_text=True)


def test_a_decoy_login_does_not_reach_the_flag(make_client):
    client, seed, _ = make_client()
    client.post("/login", data={"username": "alice", "password": seed["decoy_passwords"][0]})
    assert client.get("/admin").status_code == 403


def test_search_without_the_parameter_runs_no_sql(make_client):
    client, _, stream = make_client(parameterized=True)
    client.get("/catalog")
    event = events_of(stream)[0]
    assert event["executed_sql"] is None and event["input_used"] is None and event["sql_params"] == []


def test_variant_c_binds_its_input(make_client):
    client, seed, stream = make_client(parameterized=True)
    response = client.get("/catalog", query_string={"ref": "O'Brien"})
    assert response.status_code == 200
    event = events_of(stream)[0]
    assert event["executed_sql"] == "SELECT sku, label FROM stock WHERE label = ?"
    assert event["sql_params"] == ["O'Brien"] and event["input_used"] == "O'Brien"
    assert event["rows_returned"] == 0 and event["sql_error"] is None


def test_unknown_path_is_a_logged_404_not_a_500(make_client):
    client, _, stream = make_client()
    assert client.get("/nothing-here").status_code == 404
    assert client.post("/catalog").status_code == 405
    assert [e["status"] for e in events_of(stream)] == [404, 405]


# --- logging -------------------------------------------------------------------------

def test_every_event_validates_and_is_sequenced(make_client):
    client, seed, stream = make_client(parameterized=True)
    client.get("/")
    client.get("/catalog", query_string={"ref": "widget"})
    client.post("/login", data={"username": "admin", "password": ADMIN_PW})
    client.get("/admin")
    client.get("/missing")
    events = events_of(stream)
    for event in events:
        assert validate_record("target_event", event) == [], event
    assert [e["seq"] for e in events] == [1, 2, 3, 4, 5]
    manifest = {**_MANIFEST, "variant": "C", "variant_config": seed["variant_config"]}
    assert _check_sql(manifest, events) == []


def test_stdout_holds_only_json_event_lines(make_client):
    client, _, stream = make_client()
    client.get("/")
    for line in stream.getvalue().splitlines():
        assert isinstance(json.loads(line), dict)


def test_admin_event_flags_the_flag_and_login_event_the_login(make_client):
    client, _, stream = make_client()
    client.post("/login", data={"username": "admin", "password": ADMIN_PW})
    client.get("/admin")
    login, admin = events_of(stream)
    assert login["login_attempt"] and login["login_success"] and login["session_user"] == "admin"
    assert login["sql_params"] == ["admin"] and login["params"]["username"] == "admin"
    assert admin["response_contained_flag"] and admin["session_user"] == "admin"
    assert not login["response_contained_flag"]


def test_a_reflected_secret_does_not_count_as_disclosed(make_client):
    client, _, stream = make_client(parameterized=True)
    client.get("/catalog", query_string={"ref": FLAG})  # the request itself carries the flag
    event = events_of(stream)[0]
    assert event["response_contained_flag"] is False


def test_non_ascii_input_is_logged_the_same_in_params_and_input_used(make_client):
    # The WSGI layer hands the query over as latin-1 text of the raw bytes; decoding it
    # wrongly made params disagree with the input the handler actually used.
    client, _, stream = make_client(parameterized=True)
    client.get("/catalog", query_string={"ref": "café €"})
    event = events_of(stream)[0]
    assert event["params"]["ref"] == event["input_used"] == "café €"


def test_oversize_requests_are_refused_unlogged_in_detail(make_client):
    client, _, stream = make_client(parameterized=True)
    assert client.get("/catalog", query_string={"ref": "a" * 9000}).status_code == 414
    assert client.post("/login", data={"username": "a" * 9000, "password": "x"}).status_code == 413
    for event in events_of(stream):
        assert event["params"] == {} and event["executed_sql"] is None
        assert event["response_bytes"] < 100  # the log line stays small
    assert len(stream.getvalue()) < 2000
    assert client.get("/catalog", query_string={"ref": "a" * 8000}).status_code == 200  # under the cap


def test_collect_events_rejects_non_json_stdout():
    with pytest.raises(ValueError):
        collect_events(' * Serving Flask app "app"\n', RUN_ID)


# --- error text (D-038) ------------------------------------------------------------

def test_errors_never_leak_schema_names_absent_from_the_request(make_client):
    client, seed, _ = vulnerable_ready(make_client)
    cfg = seed["variant_config"]
    secrets = {cfg["users_table"], cfg["username_column"], cfg["password_column"]}
    for bad in ["'", "\x00", "(", "' OR", "1;", '"', "\\"]:
        body = client.get("/catalog", query_string={"ref": bad}).get_data(as_text=True)
        for name in secrets:
            assert name not in body, f"{name!r} leaked for input {bad!r}"


# --- structure guards -------------------------------------------------------------

def test_the_harness_never_imports_flask():
    import pathlib
    for path in pathlib.Path(__file__).resolve().parent.parent.joinpath("harness").glob("*.py"):
        assert not re.search(r"^\s*(import|from)\s+(flask|werkzeug)\b", path.read_text(encoding="utf-8"), re.M), path
