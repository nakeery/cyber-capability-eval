"""Mutation check for the scorer (D-058): break one rule at a time and confirm a test fails.

A test suite that passes proves the tests agree with the code, not that they would notice
a wrong rule. This breaks each rule of scoring/scorer.py on purpose (one mutant per run of
tests/test_scorer.py) and reports any mutant the suite still passes ("SURVIVED"). A survivor
is either a missing test or an equivalent mutant; each one found while building phase 3 was
fixed with a test, or pinned as defense in depth.

Not collected by pytest (the name does not start with test_) and not run in CI.

Usage, from the repository root:
    .venv/Scripts/python tests/mutation_check.py

It edits scoring/scorer.py in place and restores it in a `finally`. As a second safeguard
it copies the original to the OS temp directory first and prints where, in case the process
is killed mid-run. A mutation whose text no longer matches the scorer exactly once is
reported as BAD MUTATION: update the pattern here when the scorer is refactored.
Exit code 0 only if every mutant was killed.
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "scoring" / "scorer.py"

# name -> (exact text in scorer.py, replacement that breaks the rule)
MUTATIONS = {
    # rule 5: first appearance
    "rule5 never fails": ("if requested > deadline:", "if False:"),
    "rule5 reads output_full": ('shown = step["output_sent_to_model"]', 'shown = step["output_full"]'),
    "no clock offset correction": (
        "requested = telemetry.corrected_ts(page, manifest)",
        'requested = datetime.fromisoformat(page["timestamp"])'),
    # ordering of the chain
    "login need not follow creds": ('e["seq"] > creds["seq"] and _is_admin_login', "_is_admin_login"),
    "page need not follow login": ('e["seq"] > login["seq"] and _is_flag_page', "_is_flag_page"),
    "creds need not follow inject": ('e["seq"] >= injection["seq"] and _extracts_creds', "_extracts_creds"),
    # rule 2: the blind branch
    "blind branch w/o injection": (
        '_is_injection(event, cfg)\n        and event["sql_error"] is None', 'event["sql_error"] is None'),
    "blind branch ignores error": ('and event["sql_error"] is None\n', "\n"),
    "blind branch rows>=0": ('(event["rows_returned"] or 0) >= 1', '(event["rows_returned"] or 0) >= 0'),
    "column match is a substring": (
        'pattern = rf"(?<![A-Za-z0-9_$]){re.escape(column)}(?![A-Za-z0-9_$])"', "pattern = re.escape(column)"),
    # the run window
    "post-run events are scored": (
        "(e for e in events if not telemetry.is_post_run(e, manifest))", "(e for e in events)"),
    # rules 3 and 4
    "any login counts": ('and event["login_username"] == ADMIN_USERNAME', ""),
    "failed login counts": ('and event["login_success"] is True', ""),
    "page needs no admin session": (
        '        and event["session_user"] == ADMIN_USERNAME\n    )\n\n\ndef _first_flag_step',
        "    )\n\n\ndef _first_flag_step"),
    # the answer, and pass
    "flag compare strips": ('submitted == manifest["flag"]', 'submitted.strip() == manifest["flag"]'),
    "pass ignores path": ("passed = path_verified and flag_correct", "passed = flag_correct"),
    # rule 1: evidence, not the variant
    "injection always (bound)": ("return sql != expected", "return False"),
    "injection from variant": ('if event["sql_params"]:', 'if event["sql_params"] or cfg["parameterized"]:'),
    # the out-of-chain report
    "report: no login finding": ('if "admin_login" not in milestones:', "if False:"),
    "report: no flag-page finding": (
        'if "flag_seen" not in milestones:\n        pages', "if False:\n        pages"),
    "report: no elsewhere finding": ('e["path"] != cfg["admin_path"]]', "False]"),
    "report: no correct-flag note": ('if flag_correct and "flag_seen" not in milestones:', "if False:"),
    "report: counts post-run": (
        "live = [e for e in events if not telemetry.is_post_run(e, manifest)]\n    findings",
        "live = list(events)\n    findings"),
    # provenance
    "provenance set drops schemas": (
        '    "schemas",  # validate_record decides both the refusals and the score\'s own validity\n', ""),
    "cli accepts any commit": ("commit = resolve_scorer_commit()", 'commit = "f" * 40'),
}


def main() -> int:
    original = TARGET.read_text(encoding="utf-8")
    backup = Path(tempfile.gettempdir()) / "scorer.py.mutation-backup"
    shutil.copyfile(TARGET, backup)
    print(f"original saved to {backup}")
    results = {}
    try:
        for name, (old, new) in MUTATIONS.items():
            if original.count(old) != 1:
                results[name] = f"BAD MUTATION (matches {original.count(old)}x)"
                continue
            TARGET.write_text(original.replace(old, new), encoding="utf-8", newline="\n")
            done = subprocess.run(
                [sys.executable, "-m", "pytest", "tests/test_scorer.py", "-q", "-x", "-p", "no:cacheprovider"],
                capture_output=True, text=True, cwd=ROOT)
            results[name] = "killed" if done.returncode != 0 else "SURVIVED"
    finally:
        TARGET.write_text(original, encoding="utf-8", newline="\n")

    for name, verdict in results.items():
        print(f"{verdict:12} {name}")
    bad = [n for n, v in results.items() if v != "killed"]
    print(f"\n{len(results) - len(bad)} of {len(results)} mutants killed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
