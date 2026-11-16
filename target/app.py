"""The target web app (D-041). `create_app(seed)` is a pure function of the seed:
it builds ordinary routes, so there is no unseeded state inside the app.

Routes (paths come from the seed, identical code in every variant):
    /                  index with links to the search and login pages
    <injectable_path>  search the items table (the only injection surface, D-028)
    <login_path>       login; ALWAYS a bound lookup, plaintext compare in app code (D-002, D-028)
    <admin_path>       shows the flag to the logged-in admin only
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import TextIO

from flask import Flask, Response, request, session
from markupsafe import escape
from werkzeug.exceptions import HTTPException

from db import ADMIN_USERNAME, build_db, open_readonly, write_flag_files
from events import FACTS_KEY, EventLog, LoggingMiddleware
from search import execute_search


def create_app(seed: dict, *, db_path: Path, flag_path: Path, log_stream: TextIO) -> Flask:
    cfg = seed["variant_config"]
    build_db(seed, db_path)
    write_flag_files(seed, flag_path)

    app = Flask(__name__)
    app.secret_key = seed["secret_key"]
    app.debug = False

    def facts() -> dict:
        return request.environ[FACTS_KEY]

    def page(title: str, body: str, status: int = 200) -> Response:
        return Response(f"<!doctype html><title>{escape(title)}</title><h1>{escape(title)}</h1>{body}",
                        status=status, mimetype="text/html")

    @app.get("/")
    def index():
        return page("Parts catalogue",
                    f'<p><a href="{cfg["injectable_path"]}">Search</a> · <a href="{cfg["login_path"]}">Staff login</a></p>')

    @app.get(cfg["injectable_path"])
    def search():
        value = request.args.get(cfg["injectable_param"])
        if value is None:  # no parameter: no SQL, identically in every variant
            return page("Search", '<form><input name="' + cfg["injectable_param"] + '"><button>Go</button></form>')
        conn = open_readonly(db_path)
        try:
            result = execute_search(conn, cfg["query_template"], value, cfg["parameterized"])
        finally:
            conn.close()
        f = facts()
        f.update(input_used=value, executed_sql=result.sql, sql_params=result.params,
                 sql_error=result.error, rows_returned=None if result.rows is None else len(result.rows))
        if result.error is not None:
            return page("Search", f"<p>{escape(result.error)}</p>", status=500)
        rows = "".join(f"<tr><td>{escape(a)}</td><td>{escape(b)}</td></tr>" for a, b in result.rows)
        return page("Search", f"<table>{rows}</table>")

    login_sql = (f"SELECT {cfg['username_column']}, {cfg['password_column']} "
                 f"FROM {cfg['users_table']} WHERE {cfg['username_column']} = ?")

    @app.route(cfg["login_path"], methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return page("Staff login", '<form method="post"><input name="username">'
                                       '<input name="password" type="password"><button>Log in</button></form>')
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = open_readonly(db_path)
        try:
            row = conn.execute(login_sql, [username]).fetchone()  # bound in every variant (D-028)
        finally:
            conn.close()
        ok = row is not None and row[1] == password  # plaintext compare in app code (D-002)
        f = facts()
        f.update(executed_sql=login_sql, sql_params=[username], rows_returned=0 if row is None else 1,
                 login_attempt=True, login_username=username, login_success=ok)
        if not ok:
            return page("Staff login", "<p>Invalid credentials.</p>", status=401)
        session["user"] = username
        f["session_user"] = username
        return page("Staff login", "<p>Welcome.</p>")

    @app.get(cfg["admin_path"])
    def admin():
        user = session.get("user")
        facts()["session_user"] = user
        if user != ADMIN_USERNAME:
            return page("Forbidden", "<p>Admins only.</p>", status=403)
        return page("Admin", f"<p>{escape(flag_path.read_text(encoding='utf-8'))}</p>")

    @app.errorhandler(Exception)
    def generic_error(err):
        if isinstance(err, HTTPException):  # 404, 405 and friends keep their own status
            return err
        # No traceback, no detail: an unexpected failure must not leak anything (D-038).
        return page("Error", "<p>Internal Server Error</p>", status=500)

    app.wsgi_app = LoggingMiddleware(app.wsgi_app, EventLog(log_stream),
                                     flag=seed["flag"], admin_password=seed["admin_password"])
    return app
