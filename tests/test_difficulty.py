from types import SimpleNamespace

import pytest

from boxes import difficulty


def _step(level, kind="privesc", context="target"):
    return SimpleNamespace(
        recipe=SimpleNamespace(difficulty=level, kind=kind, poc_context=context)
    )


def _plan(user, root, ports=None):
    steps = [_step(level) for level in user] + [_step(level) for level in root]
    return SimpleNamespace(
        steps=steps,
        user_index=len(user) - 1,
        root_index=len(user) + len(root) - 1,
        ports=ports or [],
    )


def test_normalize_whole_numbers_1_to_10():
    assert difficulty.normalize(1) == 1
    assert difficulty.normalize(10) == 10
    for bad in ("easy", 0, 11, 5.0, True):
        with pytest.raises(ValueError):
            difficulty.normalize(bad)


def test_bands():
    assert difficulty.band(1) == "easy"
    assert difficulty.band(3) == "easy"
    assert difficulty.band(4) == "medium"
    assert difficulty.band(6) == "medium"
    assert difficulty.band(7) == "hard"
    assert difficulty.band(10) == "hard"


def test_machine_difficulty_is_the_hardest_step_not_a_sum():
    plan = _plan([2, 3], [5])
    summary = difficulty.report(plan)
    assert summary["machine"] == 5
    assert summary["user"] == 3
    assert summary["root"] == 5
    assert summary["band"] == "medium"
    assert summary["user_band"] == "easy"
    assert summary["root_band"] == "medium"
    # length is reported separately as shape, not folded into difficulty
    assert summary["length"] == {"user": 2, "root": 1}


def test_user_and_root_levels_are_independent():
    plan = _plan([2], [3, 8])
    summary = difficulty.report(plan)
    assert summary["machine"] == 8
    assert summary["user"] == 2
    assert summary["root"] == 8
    assert summary["user_band"] == "easy"
    assert summary["root_band"] == "hard"


def test_shape_counts_discoveries_and_context_switches():
    plan = _plan([2], [3])
    plan.steps[0] = _step(2, kind="discovery", context="attacker")
    plan.steps.append(_step(3, kind="privesc", context="target"))
    plan.root_index = 2
    summary = difficulty.report(plan)
    assert summary["discoveries"] == 1
    assert summary["context_switches"] == 1


def test_match_filters_use_bands():
    plan = _plan([2], [5])
    assert difficulty.matches(plan, machine="medium")
    assert difficulty.matches(plan, user="easy", root="medium")
    assert not difficulty.matches(plan, machine="easy")
    assert not difficulty.matches(plan, root="hard")
    assert difficulty.matches(plan)
