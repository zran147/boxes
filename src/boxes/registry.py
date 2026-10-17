"""Recipe registry: loading and OS filtering."""

from __future__ import annotations

from pathlib import Path

from .recipe import Recipe, load_recipe


def load_registry(root: str | Path) -> list[Recipe]:
    root = Path(root)
    if not root.is_dir():
        raise FileNotFoundError(f"recipe directory not found: {root}")

    recipes: list[Recipe] = []
    for path in sorted(root.glob("*/recipe.yaml")):
        recipes.append(load_recipe(path))

    seen: dict[str, Path] = {}
    for r in recipes:
        if r.id in seen:
            raise ValueError(f"duplicate recipe id {r.id!r} in {seen[r.id]} and {r.path}")
        seen[r.id] = r.path
    return recipes


def select(recipes: list[Recipe], os_name: str) -> list[Recipe]:
    return [r for r in recipes if r.applies_to(os_name)]
