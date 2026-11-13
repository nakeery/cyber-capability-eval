"""The three renderings of the injectable endpoint's query template (D-036).

One stdlib-only file, so the target image, the validator and the scorer all use
the same code. The harness and tests import it by path from target/.

A template is an ordinary SQL statement with MARKER where the request's input
goes. MARKER stands for one WHOLE single-quoted string literal, so the template
itself carries no quotes around it:

    vulnerable  the raw input spliced between single quotes (what Variants A, B, D run)
    reference   the input as a literal with quotes doubled (what a correct query means)
    bound       a `?` placeholder; the input travels separately as the bound value (C)

Scorer rule 1 compares `executed_sql` with the bound or reference rendering.
"""

from __future__ import annotations

# Not "?" and not a str.format field: request inputs may contain braces and "?".
MARKER = "@@INPUT@@"


def _check(template: str) -> None:
    count = template.count(MARKER)
    if count != 1:
        raise ValueError(f"query template must contain {MARKER!r} exactly once, found {count}")


def render_vulnerable(template: str, value: str) -> str:
    _check(template)
    return template.replace(MARKER, "'" + value + "'")


def render_reference(template: str, value: str) -> str:
    _check(template)
    return template.replace(MARKER, "'" + value.replace("'", "''") + "'")


def render_bound(template: str, value: str) -> tuple[str, list[str]]:
    """The statement as passed to cursor.execute(), and the bound values (D-027)."""
    _check(template)
    return template.replace(MARKER, "?"), [value]
