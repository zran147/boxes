"""Difficulty levels and per-machine difficulty.

Recipes carry a whole-number level from 1 (trivial) to 10 (hard). A machine's
difficulty is the hardest recipe, never a sum or mean. The user phase and root
phase are reported separately.

The CLI filters use provisional bands:

    easy:   1–3
    medium: 4–6
    hard:   7–10

Tedium (length, discoveries, service count, context switches) is reported as
``shape`` and is not folded into the difficulty level.
"""

from __future__ import annotations

from typing import Any

MIN_LEVEL = 1
MAX_LEVEL = 10
BAND_RANGES = {
    "easy": (1, 3),
    "medium": (4, 6),
    "hard": (7, 10),
}
BANDS = tuple(BAND_RANGES)
BAND_LEVELS = {"easy": 2, "medium": 5, "hard": 8}


def normalize(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"recipe difficulty must be an integer {MIN_LEVEL}-{MAX_LEVEL}, got {value!r}")
    if not MIN_LEVEL <= value <= MAX_LEVEL:
        raise ValueError(f"recipe difficulty must be within {MIN_LEVEL}-{MAX_LEVEL}, got {value}")
    return value


def band(level: int) -> str | None:
    if level is None:
        return None
    for name, (low, high) in BAND_RANGES.items():
        if low <= level <= high:
            return name
    return None


def max_level(levels) -> int:
    items = [level for level in levels if level is not None]
    return max(items) if items else 0


def report(plan) -> dict:
    steps = plan.steps
    user_steps = steps[: plan.user_index + 1]
    root_steps = steps[plan.user_index + 1 : plan.root_index + 1]
    user = max_level(step.recipe.difficulty for step in user_steps)
    root = max_level(step.recipe.difficulty for step in root_steps)
    machine = max(user, root)
    switches = sum(
        1
        for left, right in zip(steps, steps[1:])
        if left.recipe.poc_context != right.recipe.poc_context
    )
    return {
        "machine": machine,
        "user": user,
        "root": root,
        "band": band(machine),
        "user_band": band(user),
        "root_band": band(root),
        # shape, not difficulty: how long/tedious the route is
        "length": {"user": len(user_steps), "root": len(root_steps)},
        "services": len(plan.ports),
        "discoveries": sum(1 for step in steps if step.recipe.kind == "discovery"),
        "context_switches": switches,
    }


def matches(
    plan,
    machine: str | None = None,
    user: str | None = None,
    root: str | None = None,
) -> bool:
    summary = report(plan)
    return (
        (machine is None or summary["band"] == machine)
        and (user is None or summary["user_band"] == user)
        and (root is None or summary["root_band"] == root)
    )
