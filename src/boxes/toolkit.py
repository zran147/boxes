"""Attacker toolkit manifest helpers.

The YAML file is the source of truth; the Docker build context files
(tools.txt, pip.txt) are generated from it.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONTEXT = PROJECT_ROOT / "images" / "attacker"
MANIFEST = CONTEXT / "tools.yaml"


@lru_cache(maxsize=1)
def _manifest() -> dict:
    data = yaml.safe_load(MANIFEST.read_text()) or {}
    for key in ("apt", "pip", "commands"):
        value = data.get(key, [])
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError(f"{MANIFEST}: {key} must be a list of strings")
    return data


def apt_packages() -> list[str]:
    return list(_manifest().get("apt", []))


def pip_packages() -> list[str]:
    return list(_manifest().get("pip", []))


def commands() -> frozenset[str]:
    return frozenset(_manifest().get("commands", []))


def write_context() -> None:
    """Generate the plain lists the Dockerfile consumes."""
    (CONTEXT / "tools.txt").write_text("\n".join(apt_packages()) + "\n")
    (CONTEXT / "pip.txt").write_text("\n".join(pip_packages()) + ("\n" if pip_packages() else ""))
