"""The block-rate probe (harness/filter_probe.py): the statistics, the interleaving, and what an error counts as.

No AWS call is made: a fake client stands in for Bedrock. What matters here is that the numbers the probe prints
cannot be quietly wrong: a rate computed over the wrong denominator, or one arm sampled before the other, would
change the answer to the question the probe exists to ask.
"""

import json

import pytest
import filter_probe
from agent import INFERENCE_CONFIG
from filter_probe import (BLOCKED, PRICES, first_block_kind, format_summary, probe_once, run_probe, summarize,
                          wilson)
from model import ModelError, ModelReply
from prompt_set import load_prompts

PROMPTS = load_prompts()


def reply(stop="tool_use", content=None, tin=650, tout=100):
    content = [{"toolUse": {"toolUseId": "t", "name": "run_command", "input": {"command": "ls"}}}] if content is None else content
    return ModelReply(content=content, stop_reason=stop, input_tokens=tin, output_tokens=tout, request_id="req-1")


def blocked():
    return reply(BLOCKED, [{"text": "SENTINEL-MODEL-TEXT blocked by our content filters"}], tout=0)


class FakeClient:
    backend = "bedrock"

    def __init__(self, decide, model_id="fake-model"):
        self.decide, self.model_id, self.calls = decide, model_id, []

    def converse(self, *, system, messages, tool_config, inference):
        self.calls.append({"system": system, "messages": messages, "tool_config": tool_config, "inference": inference})
        outcome = self.decide(len(self.calls), system)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


# --- the interval ------------------------------------------------------------------------------

@pytest.mark.parametrize("k,n,low,high", [
    (0, 30, 0.0, 0.1135), (30, 30, 0.8865, 1.0), (15, 30, 0.3315, 0.6685), (0, 3, 0.0, 0.5615), (3, 3, 0.4385, 1.0),
])
def test_wilson_matches_known_values(k, n, low, high):
    got_low, got_high = wilson(k, n)
    assert (round(got_low, 4), round(got_high, 4)) == (low, high)


def test_wilson_with_no_data_says_nothing():
    assert wilson(0, 0) == (0.0, 1.0)


@pytest.mark.parametrize("n", [1, 5, 30, 100])
def test_wilson_stays_inside_zero_and_one_and_contains_the_estimate(n):
    for k in range(n + 1):
        low, high = wilson(k, n)
        assert 0.0 <= low <= k / n <= high <= 1.0


def test_a_larger_sample_gives_a_narrower_interval():
    widths = [wilson(n // 2, n)[1] - wilson(n // 2, n)[0] for n in (10, 30, 100)]
    assert widths == sorted(widths, reverse=True)


# --- one call ----------------------------------------------------------------------------------

@pytest.mark.parametrize("content,kind", [
    ([], "empty"), ([{"text": "hi"}], "text"), ([{"toolUse": {"name": "submit_flag"}}], "toolUse:submit_flag"),
    ([{"image": {}}], "other"),
])
def test_first_block_kind_names_the_kind_and_keeps_no_text(content, kind):
    assert first_block_kind(content) == kind


@pytest.mark.parametrize("condition", ["no_hint", "hint"])
def test_a_probe_sends_exactly_the_committed_first_turn_at_production_settings(condition):
    client = FakeClient(lambda n, system: reply())
    probe_once(client, PROMPTS, condition)
    call = client.calls[0]
    assert call["system"] == PROMPTS.system_text(condition)
    assert call["messages"] == [{"role": "user", "content": [{"text": PROMPTS.opening}]}]
    assert call["tool_config"] == PROMPTS.tool_config and call["inference"] == INFERENCE_CONFIG


def test_a_row_records_the_outcome_but_never_the_models_text():
    client = FakeClient(lambda n, system: blocked())
    row = probe_once(client, PROMPTS, "hint")
    assert row["stop_reason"] == BLOCKED and row["first_block"] == "text" and row["output_tokens"] == 0
    assert "SENTINEL-MODEL-TEXT" not in json.dumps(row)


def test_a_failed_call_is_a_row_with_an_error_kind_and_no_stop_reason():
    client = FakeClient(lambda n, system: ModelError("slow down", retries=4, kind="service"))
    row = probe_once(client, PROMPTS, "no_hint")
    assert (row["stop_reason"], row["error_kind"], row["retries"]) == (None, "service", 4)


# --- the loop of calls -----------------------------------------------------------------------------

def test_conditions_are_interleaved_call_by_call_so_neither_arm_is_sampled_first():
    seen = []
    client = FakeClient(lambda n, system: seen.append("hint" if system == PROMPTS.system_text("hint") else "no_hint") or reply())
    run_probe({"micro": client}, PROMPTS, 4, lambda row: None)
    assert seen == ["no_hint", "hint"] * 4


def test_every_cell_gets_exactly_n_calls_and_the_rounds_are_numbered():
    micro, pro = FakeClient(lambda n, s: reply(), "m"), FakeClient(lambda n, s: reply(), "p")
    rows = run_probe({"micro": micro, "pro": pro}, PROMPTS, 3, lambda row: None)
    assert len(rows) == 12 and len(micro.calls) == len(pro.calls) == 6
    assert sorted({r["round"] for r in rows}) == [1, 2, 3]
    cells = {(r["model_key"], r["condition"]) for r in rows}
    assert cells == {("micro", "no_hint"), ("micro", "hint"), ("pro", "no_hint"), ("pro", "hint")}


def test_each_row_is_handed_to_the_sink_as_it_happens():
    sunk = []
    run_probe({"micro": FakeClient(lambda n, s: reply())}, PROMPTS, 2, sunk.append)
    assert len(sunk) == 4


def test_a_run_of_failures_stops_the_probe_instead_of_recording_an_empty_measurement():
    client = FakeClient(lambda n, s: ModelError("down", kind="service"))
    with pytest.raises(RuntimeError, match="in a row failed"):
        run_probe({"micro": client}, PROMPTS, 30, lambda row: None)
    assert len(client.calls) == filter_probe.MAX_CONSECUTIVE_ERRORS


def test_scattered_failures_do_not_stop_the_probe():
    client = FakeClient(lambda n, s: ModelError("blip", kind="service") if n % 3 == 0 else reply())
    rows = run_probe({"micro": client}, PROMPTS, 10, lambda row: None)
    assert len(rows) == 20 and sum(1 for r in rows if r["error_kind"]) == 6


# --- the summary: what is counted as a block ------------------------------------------------------------

def rows_for(model, condition, stops, errors=0):
    out = [{"model_key": model, "condition": condition, "stop_reason": s, "error_kind": None,
            "input_tokens": 650, "output_tokens": 0 if s == BLOCKED else 100} for s in stops]
    out += [{"model_key": model, "condition": condition, "stop_reason": None, "error_kind": "service"} for _ in range(errors)]
    return out


def test_the_blocked_rate_counts_only_content_filtered_and_only_over_answered_calls():
    rows = rows_for("micro", "hint", [BLOCKED] * 6 + ["tool_use"] * 3 + ["end_turn"], errors=5)
    (cell,) = summarize(rows)
    assert (cell["calls"], cell["errors"], cell["answered"], cell["blocked"]) == (15, 5, 10, 6)
    assert cell["blocked_rate"] == 0.6 and cell["other_stops"] == {"tool_use": 3, "end_turn": 1}
    assert (round(cell["ci_low"], 3), round(cell["ci_high"], 3)) == tuple(round(x, 3) for x in wilson(6, 10))


def test_a_max_tokens_stop_is_not_a_block():
    (cell,) = summarize(rows_for("micro", "no_hint", ["max_tokens", "malformed_tool_use"]))
    assert cell["blocked"] == 0


def test_cells_are_kept_apart():
    rows = rows_for("micro", "no_hint", ["tool_use"] * 3) + rows_for("micro", "hint", [BLOCKED] * 3)
    by = {(c["model"], c["condition"]): c["blocked"] for c in summarize(rows)}
    assert by == {("micro", "no_hint"): 0, ("micro", "hint"): 3}


def test_a_cell_with_only_errors_has_no_rate_rather_than_a_zero():
    (cell,) = summarize(rows_for("micro", "hint", [], errors=4))
    assert cell["blocked_rate"] is None and (cell["ci_low"], cell["ci_high"]) == (0.0, 1.0)


def test_the_cost_estimate_is_tokens_times_the_price_table():
    (cell,) = summarize(rows_for("micro", "no_hint", ["tool_use"] * 10))      # 6,500 in, 1,000 out
    price_in, price_out = PRICES["micro"]
    assert cell["estimated_cost_usd"] == pytest.approx(6500 * price_in / 1e6 + 1000 * price_out / 1e6)
    (pro,) = summarize(rows_for("pro", "no_hint", ["tool_use"] * 10))
    assert pro["estimated_cost_usd"] > 20 * cell["estimated_cost_usd"] * 0.5      # Pro is far dearer per token


def test_the_printed_table_names_every_cell_and_the_interval():
    text = format_summary(summarize(rows_for("micro", "no_hint", ["tool_use"] * 4) + rows_for("micro", "hint", [BLOCKED] * 4)))
    assert "no_hint" in text and "hint" in text and "0%-" in text and "100%" in text and "estimated cost" in text


# --- the command line --------------------------------------------------------------------------------

def patch_clients(monkeypatch, decide=lambda n, s: reply()):
    made = []

    def fake_from_env(key):
        client = FakeClient(decide, model_id=key)
        made.append((key, client))
        return client

    monkeypatch.setattr(filter_probe, "bedrock_from_env", fake_from_env)
    return made


def test_the_default_is_nova_micro_only(monkeypatch, tmp_path, capsys):
    made = patch_clients(monkeypatch)
    assert filter_probe.main(["--n", "2", "--out", str(tmp_path / "rows.jsonl")]) == 0
    assert [key for key, _ in made] == ["NOVA_MICRO_MODEL_ID"]
    out = capsys.readouterr().out
    assert "2 calls per cell x 2 cells = 4 calls" in out and "micro" in out and "pro " not in out


def test_pro_is_still_available_when_asked_for(monkeypatch, tmp_path):
    made = patch_clients(monkeypatch)
    filter_probe.main(["--n", "1", "--models", "micro,pro", "--out", str(tmp_path / "rows.jsonl")])
    assert [key for key, _ in made] == ["NOVA_MICRO_MODEL_ID", "NOVA_PRO_MODEL_ID"]


def test_the_rows_file_has_one_line_per_call_and_no_model_text(monkeypatch, tmp_path):
    patch_clients(monkeypatch, decide=lambda n, s: blocked())
    path = tmp_path / "rows.jsonl"
    filter_probe.main(["--n", "3", "--out", str(path)])
    text = path.read_text(encoding="utf-8")
    lines = [json.loads(line) for line in text.splitlines()]
    assert len(lines) == 6 and all(r["stop_reason"] == BLOCKED for r in lines) and "SENTINEL-MODEL-TEXT" not in text


@pytest.mark.parametrize("argv", [["--models", "gpt"], ["--n", "0"], ["--models", ""]])
def test_bad_arguments_are_refused_before_any_call(monkeypatch, argv):
    made = patch_clients(monkeypatch)
    with pytest.raises(SystemExit):
        filter_probe.main(argv)
    assert made == []
