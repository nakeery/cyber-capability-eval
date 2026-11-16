"""The per-run seed: validation and the one-shot loader (D-033, D-041).

The harness pipes a JSON seed to `seed_loader.py` with `docker exec -i`. The loader
validates it, takes an exclusive lock (a second seed is refused) and moves it into
place atomically. `serve.py` waits for the file; there is no HTTP seed route.

Seed shape:
    variant_config   the same block the run manifest records (names, paths, template,
                     parameterized, shortcut_path for D)
    items_columns    the two column names of the items table [id-like, label-like]
    flag             the per-run flag
    admin_password   the admin's password
    decoy_passwords  four more passwords, one per decoy user (D-032)
    secret_key       the Flask session key, which exists only after seeding
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from sqltemplate import MARKER

SEED_DIR = Path("/run/seed")
SEED_NAME = "seed.json"
LOCK_NAME = ".lock"
MAX_SEED_BYTES = 64 * 1024

# Names go into CREATE TABLE and SELECT text, so they must be plain identifiers.
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,40}$")
# Secrets use an alphabet that URL-encoding and HTML-escaping leave unchanged, so the
# response_contained_* checks cannot miss a secret that holds a quote or an ampersand.
SECRET = re.compile(r"^[A-Za-z0-9_-]{24,}$")
PATH = re.compile(r"^/[A-Za-z0-9_./-]{0,60}$")

CONFIG_KEYS = {
    "injectable_path", "injectable_param", "login_path", "admin_path", "items_table",
    "users_table", "username_column", "password_column", "query_template", "parameterized",
}
DECOY_COUNT = 4


class SeedError(ValueError):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise SeedError(message)


def validate_seed(seed: object) -> dict:
    _need(isinstance(seed, dict), "seed must be a JSON object")
    _need(set(seed) == {"variant_config", "items_columns", "flag", "admin_password",
                        "decoy_passwords", "secret_key"}, "seed has missing or unknown keys")

    cfg = seed["variant_config"]
    _need(isinstance(cfg, dict), "variant_config must be an object")
    _need(CONFIG_KEYS <= set(cfg) <= CONFIG_KEYS | {"shortcut_path"}, "variant_config keys are wrong")
    for key in ("injectable_param", "items_table", "users_table", "username_column", "password_column"):
        _need(isinstance(cfg[key], str) and IDENT.match(cfg[key]), f"variant_config.{key} must be an identifier")
    for key in ("injectable_path", "login_path", "admin_path", "shortcut_path"):
        if key in cfg:
            _need(isinstance(cfg[key], str) and PATH.match(cfg[key]), f"variant_config.{key} is not a plain path")
    _need(len({cfg["injectable_path"], cfg["login_path"], cfg["admin_path"]}) == 3, "paths must differ")
    _need(isinstance(cfg["parameterized"], bool), "variant_config.parameterized must be a boolean")
    template = cfg["query_template"]
    _need(isinstance(template, str) and template.count(MARKER) == 1 and "'" not in template,
          "query_template must hold the marker once and no quotes")

    cols = seed["items_columns"]
    _need(isinstance(cols, list) and len(cols) == 2 and all(isinstance(c, str) and IDENT.match(c) for c in cols),
          "items_columns must be two identifiers")

    for key in ("flag", "admin_password", "secret_key"):
        _need(isinstance(seed[key], str) and SECRET.match(seed[key]), f"{key} fails the secret format")
    # A weak session key would let the agent forge an admin cookie: require 256 random bits
    # (secrets.token_urlsafe(32) is 43 characters).
    _need(len(seed["secret_key"]) >= 43, "secret_key must be at least 43 characters")
    decoys = seed["decoy_passwords"]
    _need(isinstance(decoys, list) and len(decoys) == DECOY_COUNT
          and all(isinstance(p, str) and SECRET.match(p) for p in decoys), "decoy_passwords fail the secret format")
    _need(len({seed["admin_password"], *decoys}) == DECOY_COUNT + 1, "passwords must all differ")
    return seed


def install_seed(raw: bytes, seed_dir: Path = SEED_DIR) -> None:
    """Validate and install a seed exactly once. Raises SeedError, or FileExistsError on a second seed."""
    _need(len(raw) <= MAX_SEED_BYTES, "seed is too large")
    try:
        seed = validate_seed(json.loads(raw))
    except json.JSONDecodeError:
        raise SeedError("seed is not valid JSON") from None
    seed_dir.mkdir(parents=True, exist_ok=True)
    # "x" fails if the lock already exists: the second seed is refused, never merged.
    with open(seed_dir / LOCK_NAME, "x"):
        pass
    tmp = seed_dir / (SEED_NAME + ".tmp")
    tmp.write_text(json.dumps(seed), encoding="utf-8")
    os.replace(tmp, seed_dir / SEED_NAME)  # atomic: serve.py never sees a half-written seed


def load_seed(seed_dir: Path = SEED_DIR) -> dict:
    return json.loads((seed_dir / SEED_NAME).read_text(encoding="utf-8"))


def main() -> int:
    try:
        install_seed(sys.stdin.buffer.read(MAX_SEED_BYTES + 1))
    except SeedError as err:
        print(f"seed rejected: {err}", file=sys.stderr)
        return 2
    except FileExistsError:
        print("seed rejected: a seed was already installed", file=sys.stderr)
        return 3
    return 0
