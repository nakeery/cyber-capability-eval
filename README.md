# Cyber-Capability Evaluation Lab

A small, rigorous evaluation of whether an LLM agent (Amazon Nova Micro on Bedrock, with Nova Pro as a pre-registered fallback) can exploit a deliberately vulnerable web app, and, more importantly, **which apparent successes are genuine capability versus evaluation artifacts**: familiar naming, leakage, scoring errors and environment flaws.

> **Status:** phases 0 to 3 are built (foundations, telemetry contract, target app and variants, scorer); phase 4 (the agent harness) is next. See [PLAN.md](PLAN.md) for the full plan and [DECISIONS.md](DECISIONS.md) for every design decision and why.

## What it does

- **Target:** a Flask + SQLite app with a two-step chain: SQL injection → credential extraction → admin login → flag.
- **Variants:** A (familiar naming), B (novel naming), C (patched control), D (one planted shortcut).
- **Harness:** a minimal agent loop on the Bedrock Converse API with two tools (`run_command` in a sandboxed attacker container, and a one-shot `submit_flag`).
- **Scoring:** a deterministic, full-chain scorer built from the target's raw event log, cross-checked against a trajectory labeler that is itself validated by hand.
- **Containment:** hardened containers on an internal-only network, preflight egress tests, and per-run secrets that never touch argv, env vars or image layers.

## Layout

| Path | Contents |
|---|---|
| `PLAN.md` | Phases, exit criteria, risks |
| `DECISIONS.md` | Append-only decision log |
| `target/`, `attacker/` | The vulnerable Flask app and its image; the container the agent's commands run in |
| `scoring/` | The deterministic scorer: `python scoring/scorer.py <run_dir>` |
| `harness/` | Agent loop, Bedrock client, run orchestration, telemetry validator (the agent loop is phase 4) |
| `schemas/` | JSON schemas for the four telemetry records and the outcome labels |
| `tests/` | pytest suites (`.venv/Scripts/python -m pytest`) |
| `infra/bootstrap/` | One-time AWS setup: scoped IAM user and budget alarm |
| `.claude/agents/` | Review agents used throughout the project |

## Setup (phase 0)

Requirements: Python 3.13, the AWS CLI, Docker Engine 26 or later (from phase 2).

1. Follow [infra/bootstrap/README.md](infra/bootstrap/README.md) to create the scoped `model-eval` AWS profile and the budget alarm.
2. Create the environment:

   ```bash
   py -3.13 -m venv .venv
   ```

   ```bash
   .venv/Scripts/python -m pip install -r requirements.txt
   ```

3. Copy `.env.example` to `.env` (no secrets go in it).
4. Run the Bedrock smoke test:

   ```bash
   .venv/Scripts/python harness/smoke_test.py
   ```

## Safety

The agent under test runs only inside an isolated container with no network egress. It never sees AWS credentials, and the vulnerable app runs only inside that isolated lab network.
