import random
import re
from pathlib import Path

import pytest

from boxes.manifest import materialize
from boxes.planner import generate, is_relevant, satisfies
from boxes.registry import load_registry, select
from boxes.writeup import plan_to_dict, render_markdown

RECIPES = Path(__file__).resolve().parents[1] / "recipes"
OS = "ubuntu-22.04"


@pytest.fixture(scope="module")
def pool():
    return select(load_registry(RECIPES), OS)


@pytest.mark.parametrize("to_user,to_root", [(1, 1), (1, 2), (2, 1), (3, 1), (2, 2), (3, 2)])
@pytest.mark.parametrize("seed", [0, 1, 7, 42, 1337, 99999])
def test_generated_machines_are_valid(pool, to_user, to_root, seed):
    plan = generate(pool, OS, to_user, to_root, seed)
    assert plan is not None, f"no machine for {to_user}/{to_root} seed {seed}"

    # exact step counts
    assert plan.user_index == to_user - 1
    assert plan.root_index == to_user + to_root - 1

    # flag steps carry the right tag
    assert "user" in plan.steps[plan.user_index].recipe.yields
    assert "root" in plan.steps[plan.root_index].recipe.yields

    # every precondition was actually met, in order
    assert satisfies(plan)

    # and it is a causal chain (no filler steps)
    assert is_relevant(plan)


def test_infeasible_depth_returns_none(pool):
    # with the shipped recipe graph there is no 4-step chain to the user flag
    assert generate(pool, OS, 4, 1, 1) is None


def test_deterministic_under_same_seed(pool):
    a = generate(pool, OS, 3, 2, 123)
    b = generate(pool, OS, 3, 2, 123)
    assert [s.recipe.id for s in a.steps] == [s.recipe.id for s in b.steps]
    ma = materialize(a, 123)
    mb = materialize(b, 123)
    assert ma.values == mb.values


def test_writeup_has_no_unresolved_placeholders(pool):
    for seed in range(20):
        plan = generate(pool, OS, 3, 2, seed)
        m = materialize(plan, seed)
        text = render_markdown(plan, m) + str(plan_to_dict(plan, m))
        assert not re.findall(r"\{[A-Za-z0-9_.]+\}", text), f"seed {seed}"


def test_leaked_credentials_are_the_ones_used(pool):
    """The FTP recipe leaks creds; the SSH foothold must use exactly those."""
    plan = None
    for seed in range(200):
        p = generate(pool, OS, 3, 2, seed)
        if p and any(s.recipe.id == "ftp-config-leak-creds" for s in p.steps):
            plan = p
            break
    assert plan is not None, "no ftp chain found"

    m = materialize(plan, 0)
    leak = next(s for s in plan.steps if s.recipe.id == "ftp-config-leak-creds")
    foothold = next(s for s in plan.steps if s.recipe.id == "ssh-creds-foothold")

    leak_ctx = m.step_context(leak)
    foot_ctx = m.step_context(foothold)
    assert leak_ctx["ssh_user"] == foot_ctx["u"]
    assert leak_ctx["ssh_pass"] == foot_ctx["p"]


def test_single_step_rce_is_reachable_at_depth_one(pool):
    plan = generate(pool, OS, 1, 1, 3)
    assert plan is not None
    assert plan.steps[0].recipe.kind == "foothold"
    assert "user" in plan.steps[0].recipe.yields
