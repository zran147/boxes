from types import SimpleNamespace

import pytest

from boxes import difficulty


def _step(band, kind="privesc", context="target"):
    return SimpleNamespace(
        recipe=SimpleNamespace(difficulty=band, kind=kind, poc_context=context)
    )


def _plan(user, root, ports=None):
    steps = [_step(band) for band in user] + [_step(band) for band in root]
    return SimpleNamespace(
        steps=steps,
        user_index=len(user) - 1,
        root_index=len(user) + len(root) - 1,
        ports=ports or [],
    )


def test_normalize_bands_and_legacy_numbers():
    assert difficulty.normalize("Easy") == "easy"
    assert difficulty.normalize("medium") == "medium"
    assert difficulty.normalize(0.1) == "easy"
    assert difficulty.normalize(0.5) == "medium"
    assert difficulty.normalize(0.8) == "hard"
    with pytest.raises(ValueError):
        difficulty.normalize("insane")
    with pytest.raises(ValueError):
        difficulty.normalize(1.5)


def test_machine_difficulty_is_the_hardest_step_not_a_sum():
    plan = _plan(["easy", "easy"], ["medium"])
    summary = difficulty.report(plan)
    assert summary["machine"] == "medium"
    assert summary["user"] == "easy"
    assert summary["root"] == "medium"
    # length is reported separately as shape, not folded into difficulty
    assert summary["length"] == {"user": 2, "root": 1}


def test_user_and_root_bands_are_independent():
    plan = _plan(["easy"], ["easy", "hard"])
    summary = difficulty.report(plan)
    assert summary["machine"] == "hard"
    assert summary["user"] == "easy"
    assert summary["root"] == "hard"


def test_shape_counts_discoveries_and_context_switches():
    plan = _plan(["easy"], ["easy"])
    plan.steps[0] = _step("easy", kind="discovery", context="attacker")
    plan.steps.append(_step("easy", kind="privesc", context="target"))
    # user/root indexes are stale after the append; use a fresh report shape
    plan.root_index = 2
    summary = difficulty.report(plan)
    assert summary["discoveries"] == 1
    assert summary["context_switches"] == 1


def test_matches_requires_exact_bands():
    plan = _plan(["easy"], ["medium"])
    assert difficulty.matches(plan, machine="medium")
    assert difficulty.matches(plan, user="easy", root="medium")
    assert not difficulty.matches(plan, machine="easy")
    assert not difficulty.matches(plan, root="hard")
    assert difficulty.matches(plan)
