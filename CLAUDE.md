# CLAUDE.md

Guidance for any Claude session working in this repo. Read [PLAN.md](PLAN.md) for the phases and [DECISIONS.md](DECISIONS.md) for every design decision (D-001…) and its rationale. These two files are the source of truth; this file is the short orientation.

## What this is

A small, rigorous **cyber-capability evaluation lab**: an LLM agent attacks a deliberately vulnerable Flask/SQLite app (SQL injection → credential extraction → admin login → flag) inside a hardened, network-isolated sandbox. The point is not just "can the agent do it" but **which apparent successes are genuine capability vs. evaluation artifacts** (familiar naming, leakage, scoring errors, environment flaws). It's a portfolio project for an AI-security evaluation role; depth over breadth.

## Status

Phases 0 (foundations) and 1 (telemetry contract) are on `main` (PR #1 merged). Phase 1 was a structure pass: the skeleton fake runs held `<FILL: ...>` placeholders until phase 2 filled them (D-035). The pre-phase-2 decisions D-027 to D-039 are accepted (D-036 to D-039 amend D-027, D-029, D-010, D-030 and D-035 after the phase 2 readiness reviews); the schema, validator and fixture changes they imply (`sql_params`, `query_template`, `clock_offset_ms`, `clock_uncertainty_ms`, `seq`) are committed on `phase-2-target` (D-040). D-040's six reviewer findings are now resolved: item 1 (the variant registry) by D-047; item 4 (strict secret formats) was already closed by D-041; items 2, 3, 5 and 6 are deferred to phases 3-5, where they're recorded as constraints, not phase 2 blockers. The target app (`target/`, D-041), its Dockerfiles and compose files (D-034), and a first containment audit (D-042) are committed on `phase-2-target` and accepted by the author, who wrote the vulnerable search branch locally.

**Phase 2 is complete**, per PLAN.md's exit criteria. `harness/hand_lab.py` (D-043) ran the hand-exploit by hand for all four variants: A, B and D's full chains, a blind-extraction attempt on B (D-035's rare-label guarantee), C's resist-check (clean on the inputs it was actually run against — zero `sql_error`, rows at an ordinary baseline, no disclosure — but only a handful of B's successful inputs were replayed against C, not an exhaustive replay of every technique that worked on B; D-051 tracks closing that gap), and a live session confirming the UNION-against-the-flag check (schema enumeration found nothing flag-shaped; a stacked-statement/`ATTACH` attempt was rejected at the driver level). `target/variant_registry.py` (D-047) is now the single source of the four variants' names — both `hand_lab.py` and the skeleton builder derive their own copies from it, and the validator checks every run's `variant_config` against it directly, closing D-040's item 1. `tests/fixtures/skeletons/fill_locally.py` (D-044, D-045, D-046, D-048) fills every fillable field from a real run: `target_events.jsonl`'s request-tied fields via `apply`, and `steps.jsonl`'s `tool_input.command`/`output_full`/`output_sent_to_model` via the newer `apply-steps` (D-048), which derives both mechanically from a skeleton's own already-filled data rather than needing a transcript that was never recorded. Each skeleton's `assistant_text` and `recon` step are authored directly (not attack content). All six fillable skeletons in the gitignored `tests/fixtures/skeletons_filled/` are completely filled and pass validation; `manifest.admin_password` is now kept in sync with each one's real login password (D-050). PLAN.md's phase 2 contract-additions bullet claimed three validator checks (`step_cap`, credentials off the injectable path, `flag_correct`) that weren't actually implemented; they're added now, with tests (D-052).

**Phase 3 (scorer) is built on `phase-3-scorer` and signed off with conditions by the `methodology-reviewer` (D-058); not yet merged.** D-055 to D-057 fix what the score's fields mean, how the chain is walked and the scorer's refusals; `scoring/scorer.py` implements them and `tests/test_scorer.py` covers PLAN.md's synthetic cases. The scorer reproduces all six filled skeletons exactly (locally; the filled fixtures are gitignored, so CI skips that test). `tests/mutation_check.py` breaks 25 scorer rules one at a time and checks a test fails each time (all 25 are killed); building it exposed five test gaps, one of them an equivalent mutant, all fixed or pinned. Two committed skeleton scores changed to match D-055 (`partial_flag_seen_wrong_submit`, `shortcut_d_hybrid`). The review's findings, in short (D-058): the floor check keys on `admin_login`, because `creds_extracted` can be earned incidentally; Variant C is a leak detector, not a test of the scorer; "did any agent find the shortcut" never comes from `flag_correct` and not `path_verified`; and the scorer prints an out-of-chain report (leaks and rule-2 false fails) beside each verdict. The conditions that remain open sit in PLAN.md's phases 4 to 8: seven things the harness must guarantee (first among them, a step's `started_at`/`ended_at` bound the tool execution), the API-error exclusion rule, and the sqlmap baseline's metric. Next: phase 4 (harness).

## How to work here

- **One model.** Nova Micro is the only evaluated model; Nova Pro is a pre-registered floor-check fallback, not a second arm (D-023). Don't reintroduce a two-model comparison.
- **Every design choice gets a decision entry.** Append to DECISIONS.md (never edit past entries; supersede with a new D-NNN and a note on the old one). Keep PLAN.md and the review agents in sync when a decision changes them.
- **Commit only when the user asks.** Branch for new work; `main` is the integration branch. Scan staged files for secrets before every commit.
- **Implement code yourself and explain it** in insight blocks. Do **not** leave `TODO(human)` sections or "Learn by Doing" exercises — the user has asked for walkthroughs at a later date instead.
- Tests: `.venv/Scripts/python -m pytest`. Python 3.13; dependencies pinned in requirements.txt. After changing `scoring/scorer.py`, also run `.venv/Scripts/python tests/mutation_check.py` (every mutant must be killed; it is not part of the pytest run).
- **Mechanical work can go to `mechanical-coder`/`routine-checker` (Haiku, D-054), one precisely-specified sub-task per call, scoped to a single phase's work at a time.** The orchestrating session is the one that verifies and fixes their output — never trust a Haiku worker's report as the last check. Judgment-heavy work (design, methodology, containment, labeling) stays on the existing review agents; don't move it to a worker agent to save tokens.

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
| `scoring/` | The deterministic scorer (D-055 to D-057): `python scoring/scorer.py <run_dir>`; tests in `tests/test_scorer.py` |
| `target/`, `attacker/` | The vulnerable Flask app and its image; the container the agent's commands run in |
| `docker-compose.yml`, `docker-compose.d.yml` | The internal-only lab network; the D override adds one read-only flag volume |
| `tests/` | pytest suites; `tests/fixtures/skeletons/` holds the placeholder fake runs and `fill_locally.py` (D-044) |
| `infra/bootstrap/` | One-time AWS setup (scoped IAM user, budget) |
| `.claude/agents/` | Review agents (read-only, judgment-heavy): architecture-advisor, methodology-reviewer, containment-auditor, trajectory-analyst, skeleton-labeler. Worker agents (Haiku, mechanical work, D-054): mechanical-coder, routine-checker |
