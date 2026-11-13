"""The three template renderings, pinned with literal golden strings (D-036).

The app, validator and scorer all import the same module, so a bug in it would
be shared by all of them and no cross-check would see it. Only literal expected
strings can. Values are harmless: an ordinary name, and one with an apostrophe.
"""

import pytest
from sqltemplate import MARKER, render_bound, render_reference, render_vulnerable

TEMPLATE = "SELECT sku, label FROM stock WHERE label = " + MARKER


def test_vulnerable_splices_the_raw_value_between_quotes():
    assert render_vulnerable(TEMPLATE, "widget") == "SELECT sku, label FROM stock WHERE label = 'widget'"
    assert render_vulnerable(TEMPLATE, "O'Brien") == "SELECT sku, label FROM stock WHERE label = 'O'Brien'"


def test_reference_doubles_quotes():
    assert render_reference(TEMPLATE, "widget") == "SELECT sku, label FROM stock WHERE label = 'widget'"
    assert render_reference(TEMPLATE, "O'Brien") == "SELECT sku, label FROM stock WHERE label = 'O''Brien'"


def test_bound_uses_a_placeholder_and_returns_the_value():
    assert render_bound(TEMPLATE, "O'Brien") == ("SELECT sku, label FROM stock WHERE label = ?", ["O'Brien"])


def test_without_a_quote_vulnerable_equals_reference_and_with_one_they_differ():
    assert render_vulnerable(TEMPLATE, "widget") == render_reference(TEMPLATE, "widget")
    assert render_vulnerable(TEMPLATE, "O'Brien") != render_reference(TEMPLATE, "O'Brien")


def test_braces_and_question_marks_in_the_value_are_inert():
    value = "{0} ? @@"
    assert render_vulnerable(TEMPLATE, value).endswith("= '{0} ? @@'")
    assert render_bound(TEMPLATE, value)[1] == [value]


@pytest.mark.parametrize("template", ["SELECT 1", MARKER + " " + MARKER])
def test_marker_must_appear_exactly_once(template):
    for render in (render_vulnerable, render_reference, render_bound):
        with pytest.raises(ValueError):
            render(template, "x")
