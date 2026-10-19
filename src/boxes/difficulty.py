"""Difficulty bands and per-machine difficulty.

Difficulty is a property of the hardest recipe in a phase, not a sum of recipe
scores. Tedium (length, discoveries, service count, context switches) is
reported separately as ``shape`` so a long easy machine is not mislabelled as
hard.
"""

from __future__ import annotations

from typing import Any

BANDS = ("easy", "medium", "hard")
_RANK = {band: index for index, band in enumerate(BANDS)}


def normalize(value: Any) -> str:
    """Accept a band or a legacy 0..1 number and return a band."""
    if isinstance(value, str):
        band = value.strip().lower()
        if band in _RANK:
            return band
        raise ValueError(
            f"difficulty must be one of {BANDS} or a number in [0, 1], got {value!r}"
        )
    try:
        score = float(value)
    except (TypeError, ValueError):
        raise ValueError(
            f"difficulty must be one of {BANDS} or a number in [0, 1], got {value!r}"
        )
    if not 0.0 <= score <= 1.0:
        raise ValueError(f"difficulty must be within [0, 1], got {score}")
    if score < 1 / 3:
        return "easy"
    if score < 2 / 3:
        return "medium"
    return "hard"


def max_band(bands) -> str | None:
    items = [band for band in bands if band is not None]
    if not items:
        return None
    return max(items, key=lambda band: _RANK[band])


def report(plan) -> dict:
    steps = plan.steps
    user_steps = steps[: plan.user_index + 1]
    root_steps = steps[plan.user_index + 1 : plan.root_index + 1]
    user = max_band(step.recipe.difficulty for step in user_steps)
    root = max_band(step.recipe.difficulty for step in root_steps)
    machine = max_band([user, root])
    switches = sum(
        1
        for left, right in zip(steps, steps[1:])
        if left.recipe.poc_context != right.recipe.poc_context
    )
    return {
        "machine": machine,
        "user": user,
        "root": root,
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
        (machine is None or summary["machine"] == machine)
        and (user is None or summary["user"] == user)
        and (root is None or summary["root"] == root)
    )
