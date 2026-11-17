# Cyber-Capability Evaluation Lab

A small, rigorous evaluation of whether an LLM agent (a pinned, locally served open-weight model, Qwen3-8B, D-067 and D-068; the harness also has a Bedrock backend for Amazon Nova) can exploit a deliberately vulnerable web app, and, more importantly, **which apparent successes are genuine capability versus evaluation artifacts**: familiar naming, leakage, scoring errors and environment flaws.

> **Status:** phases 0 to 4 are built (foundations, telemetry contract, target app and variants, scorer, the agent harness with its local-model backend); phase 5 (baselines, pilot, the local model's floor check) is next, once the risks D-072 lists as open before it are resolved. See [PLAN.md](PLAN.md) for the full plan and [DECISIONS.md](DECISIONS.md) for every design decision and why.

## What it does

- **Target:** a Flask + SQLite app with a two-step chain: SQL injection → credential extraction → admin login → flag.
- **Variants:** A (familiar naming), B (novel naming), C (patched control), D (one planted shortcut).
- **Harness:** a minimal agent loop behind one model-call function (a local `llama-server`, or the Bedrock Converse API) with two tools (`run_command` in a sandboxed attacker container, and a one-shot `submit_flag`).
- **Scoring:** a deterministic, full-chain scorer built from the target's raw event log, cross-checked against a trajectory labeler that is itself validated by hand.
- **Containment:** hardened containers on an internal-only network, preflight egress tests, and per-run secrets that never touch argv, env vars or image layers.

## Layout

| Path | Contents |
|---|---|
| `PLAN.md` | Phases, exit criteria, risks |
| `DECISIONS.md` | Append-only decision log |
| `target/`, `attacker/` | The vulnerable Flask app and its image; the container the agent's commands run in |
| `scoring/` | The deterministic scorer: `python scoring/scorer.py <run_dir>` |
| `harness/` | Agent loop, model clients (local and Bedrock), run orchestration, preflight, telemetry validator (phase 4) |
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

## Testing the local model (D-067 to D-069)

The evaluated model runs on the HOST, in `llama-server`, never in a container: only the command text it writes reaches the attacker container. These commands exercise it on synthetic prompts, with no lab involved. They assume the setup of D-067 (the runtime, the weights and the API key under `G:\model-eval-local\`).

1. Start the server. It is started from `harness/local_pin.json`'s flags, refuses to start if something holds the port, and is stopped again if it listens beyond loopback:

   ```bash
   powershell -NoProfile -File harness/local_server.ps1 start
   ```

2. Check the committed pin against the running server (it only renders the study prompt, it never asks the model to answer it). Every line should say PASS:

   ```bash
   .venv/Scripts/python harness/local_check.py
   ```

3. Run the spike: 30 benign shell tasks at the production sampling through the loop's own strict classifier, the turn after an unhelpful tool result, and the context window (about 5 minutes; `--n 6 --follow-ups 3 --window 2000,8000` is the 1-minute version):

   ```bash
   .venv/Scripts/python harness/local_spike.py
   ```

4. Optionally, run the rehearsal (D-071): the real loop and the real parser on real model output, with a fake lab, made-up prompts and a simulated shell that starts no process. It never touches the study prompt or Docker, and takes about 40 seconds:

   ```bash
   .venv/Scripts/python -m pytest tests/test_local_rehearsal.py -v -s
   ```

5. Stop the server (it kills only a process whose executable is the pinned runtime):

   ```bash
   powershell -NoProfile -File harness/local_server.ps1 stop
   ```

`powershell -NoProfile -File harness/local_server.ps1 status` shows whether it is running and what it listens on. Results go to `runs/local_spike/` (gitignored). To test a different model, give it its own pin file (`LOCAL_LLM_PIN` in `.env`) and see D-068 for what else changes.

## Safety

The agent under test runs only inside an isolated container with no network egress. It never sees AWS credentials, and the vulnerable app runs only inside that isolated lab network.
