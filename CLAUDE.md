# CLAUDE.md

Guidance for any Claude session working in this repo. Read [PLAN.md](PLAN.md) for the phases and [DECISIONS.md](DECISIONS.md) for every design decision (D-001…) and its rationale. These two files are the source of truth; this file is the short orientation.

## What this is

A small, rigorous **cyber-capability evaluation lab**: an LLM agent attacks a deliberately vulnerable Flask/SQLite app (SQL injection → credential extraction → admin login → flag) inside a hardened, network-isolated sandbox. The point is not just "can the agent do it" but **which apparent successes are genuine capability vs. evaluation artifacts** (familiar naming, leakage, scoring errors, environment flaws). It's a portfolio project for an AI-security evaluation role; depth over breadth.

## Status

Phases 0 (foundations) and 1 (telemetry contract) are on `main` (PR #1 merged). Phase 1 is a structure pass: the skeleton fake runs still hold `<FILL: ...>` placeholders, to be filled locally at the end of phase 2 (D-035). The pre-phase-2 decisions D-027 to D-039 are accepted (D-036 to D-039 amend D-027, D-029, D-010, D-030 and D-035 after the phase 2 readiness reviews); the schema, validator and fixture changes they imply (`sql_params`, `query_template`, `clock_offset_ms`, `clock_uncertainty_ms`, `seq`) are committed on `phase-2-target` (D-040; D-040 lists six reviewer findings still awaiting the author's call). The target app (`target/`, D-041), its Dockerfiles and compose files (D-034), and a first containment audit (D-042) are committed on `phase-2-target` and accepted by the author, who wrote the vulnerable search branch locally. `harness/hand_lab.py` (D-043) starts a lab for the hand-exploit, which the author has run for A, B and D. `tests/fixtures/skeletons/fill_locally.py` (D-044) fills a skeleton's three request-tied fields from a real run and reports everything else as a gap, into the gitignored `tests/fixtures/skeletons_filled/`. Remaining phase 2 work: C's resist-check, a blind-extraction attempt, the UNION-against-the-flag check, the variant registry, then the skeleton fill itself (D-035, D-039).

## How to work here

- **One model.** Nova Micro is the only evaluated model; Nova Pro is a pre-registered floor-check fallback, not a second arm (D-023). Don't reintroduce a two-model comparison.
- **Every design choice gets a decision entry.** Append to DECISIONS.md (never edit past entries; supersede with a new D-NNN and a note on the old one). Keep PLAN.md and the review agents in sync when a decision changes them.
- **Commit only when the user asks.** Branch for new work; `main` is the integration branch. Scan staged files for secrets before every commit.
- **Implement code yourself and explain it** in insight blocks. Do **not** leave `TODO(human)` sections or "Learn by Doing" exercises — the user has asked for walkthroughs at a later date instead.
- Tests: `.venv/Scripts/python -m pytest`. Python 3.13; dependencies pinned in requirements.txt.

## Safety note (important)

A safety classifier repeatedly **stops responses that author realistic attack content** (SQL injection payloads, exploit strings), even for this legitimate, contained eval. The project works around this (D-024, D-026, D-035): fake runs are authored as **skeletons** with attack-specific fields left as `<FILL: ...>` role descriptors, and structural fields concrete. The literal payloads, SQL and the real target app are filled in / built **locally**, not in the chat channel: the target app in phase 2, the skeleton fill at the end of phase 2 (D-035; local and gitignored, D-039), and real pilot content in phase 5. If you hit a stop, don't retry the same content — keep attack specifics as placeholders and hand the fill to the user.

## Security invariants (don't regress these)

- **AWS:** local runs use the scoped `model-eval` profile (IAM user `model-eval-lab`, `bedrock:InvokeModel` on two Nova ARNs only). The harness refuses any other identity, including root/admin, and reads the profile from `.env`, ignoring a machine-wide `AWS_PROFILE` (D-021, D-022). Never run with root or admin credentials. AWS account changes are the user's to make.
- **Secrets never enter git:** `.env`, `~/.aws`, `runs/`, `budget-notifications.local.json` are gitignored. Per-run flag/password live only in `runs/`; `results/` copies are redacted (enforced by the manifest schema's `redacted` rule).
- **Containment (from phase 2 on):** internal-only Docker networks, non-root/read-only/cap-dropped containers, argv-only `docker exec`, secrets piped on stdin, preflight egress/DNS/IMDS checks. The agent under test never sees AWS credentials.
- **Line endings:** `.gitattributes` forces LF (scripts/SQL run in Linux containers).

## Privacy

The user's email and AWS account ID are private. Never put them in external requests; mask the account ID in output. The email goes only in the gitignored `budget-notifications.local.json`.

## Layout

| Path | Contents |
|---|---|
| `PLAN.md`, `DECISIONS.md` | Phases/exit criteria; append-only decision log |
| `schemas/` | JSON Schemas for the four telemetry records + outcome labels |
| `harness/` | Bedrock smoke test, telemetry validator, target-log collector, `hand_lab.py` (local lab starter for the hand-exploit; phase 4 supersedes it) |
| `target/`, `attacker/` | The vulnerable Flask app and its image; the container the agent's commands run in |
| `docker-compose.yml`, `docker-compose.d.yml` | The internal-only lab network; the D override adds one read-only flag volume |
| `tests/` | pytest suites; `tests/fixtures/skeletons/` holds the placeholder fake runs and `fill_locally.py` (D-044) |
| `infra/bootstrap/` | One-time AWS setup (scoped IAM user, budget) |
| `.claude/agents/` | Review agents: architecture-advisor, methodology-reviewer, containment-auditor, trajectory-analyst, skeleton-labeler |
