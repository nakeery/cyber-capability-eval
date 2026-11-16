"""The injectable search (D-027, D-036, D-041).

`execute_search` picks the statement and its bound values, makes ONE
`cursor.execute(sql, params)` call, and reports those same two variables, so
`executed_sql` is the string handed to the driver by construction.

Variant C binds its input. Variants A, B and D splice it into the statement text;
that one branch is written by the author locally (D-024, CLAUDE.md safety note),
and must be committed before image digests are recorded.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from sqltemplate import render_bound, render_vulnerable

MAX_ROWS = 50
# A fixed SQLite virtual-machine instruction budget per statement. Deterministic, unlike
# a wall-clock limit, so a runaway query fails the same way in every variant and shows
# up as an ordinary sql_error ("interrupted").
VM_BUDGET_OPS = 5_000_000
PROGRESS_EVERY = 1_000


@dataclass
class SearchResult:
    sql: str
    params: list[str]
    rows: list[tuple] | None
    error: str | None


def choose_statement(template: str, value: str, parameterized: bool) -> tuple[str, list[str]]:
    """The statement and bound values for this request."""
    if parameterized:
        return render_bound(template, value)
    # HANDOFF (author, locally): the vulnerable rendering of `template` with `value`
    # spliced in, returned as (statement, []). target/sqltemplate.py already provides
    # the rendering function. See D-041.
    return render_vulnerable(template, value), []


def execute_search(conn: sqlite3.Connection, template: str, value: str, parameterized: bool) -> SearchResult:
    sql, params = choose_statement(template, value, parameterized)
    budget = {"ops": 0}

    def stop_runaway() -> int:
        budget["ops"] += PROGRESS_EVERY
        return 1 if budget["ops"] > VM_BUDGET_OPS else 0  # non-zero aborts the statement

    conn.set_progress_handler(stop_runaway, PROGRESS_EVERY)
    try:
        rows = conn.execute(sql, params).fetchmany(MAX_ROWS)
        return SearchResult(sql, params, rows, None)
    except (sqlite3.Error, ValueError) as err:
        # The driver's message only: never the statement, a traceback or a schema dump (D-038).
        return SearchResult(sql, params, None, str(err))
    finally:
        conn.set_progress_handler(None, 0)
