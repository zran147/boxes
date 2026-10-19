"""Content-addressed verification cache.

A cache entry is keyed by the *content* of everything that can change the
outcome: the recipe directory (yaml, provision, poc, assets), the grounded
fixture/manifest values, the base image ID, and the backend fidelity. A hit
means "this exact recipe+input already passed on this exact image", so there is
no point spinning a container again.

Only successful verifications are stored, so failures are always retried.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

from .manifest import Manifest
from .planner import Plan

CACHE_VERSION = 1
# Bump this whenever verification *semantics* change (not recipe content), e.g.
# moving PoCs from the target to the attacker container. Without it, old cache
# entries would wrongly survive a runner change.
SEMANTICS_VERSION = 4


def _h(*parts) -> "hashlib._Hash":
    h = hashlib.sha256()
    for part in parts:
        h.update(part if isinstance(part, bytes) else str(part).encode())
        h.update(b"\0")
    return h


def recipe_key(recipe, ctx: dict, image_id: str, fidelity: str) -> str:
    h = _h(
        "recipe-v1",
        SEMANTICS_VERSION,
        recipe.id,
        image_id,
        fidelity,
        json.dumps(ctx, sort_keys=True, default=str),
    )
    root = recipe.dir
    for path in sorted(root.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            h.update(str(path.relative_to(root)).encode())
            h.update(b"\0")
            h.update(path.read_bytes())
    return h.hexdigest()


def machine_key(plan: Plan, manifest: Manifest, image_id: str, fidelity: str) -> str:
    h = _h(
        "machine-v1",
        SEMANTICS_VERSION,
        plan.os_name,
        plan.seed,
        manifest.build_seed,
        image_id,
        fidelity,
    )
    for step in plan.steps:
        h.update(step.instance.encode())
        h.update(b"\0")
        h.update(recipe_key(step.recipe, manifest.step_context(step), image_id, fidelity).encode())
    return h.hexdigest()


class Cache:
    def __init__(self, path: str | Path, enabled: bool = True) -> None:
        self.path = Path(path)
        self.enabled = enabled
        self._data: dict = {"version": CACHE_VERSION, "entries": {}}
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError):
            return
        if data.get("version") == CACHE_VERSION:
            self._data = data

    def get(self, key: str) -> dict | None:
        if not self.enabled:
            return None
        return self._data["entries"].get(key)

    def put(self, key: str, value: dict) -> None:
        if not self.enabled:
            return
        self._data["entries"][key] = {"at": time.time(), **value}
        self._save()

    def clear(self) -> None:
        self._data = {"version": CACHE_VERSION, "entries": {}}
        self._save()

    def __len__(self) -> int:
        return len(self._data["entries"])

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".cache-", text=True)
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(self._data, fh, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
