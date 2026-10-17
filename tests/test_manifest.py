import random
from pathlib import Path

from boxes.manifest import derive_seed, generate_param, materialize
from boxes.planner import generate
from boxes.recipe import ParamSpec
from boxes.registry import load_registry, select

RECIPES = Path(__file__).resolve().parents[1] / "recipes"
OS = "ubuntu-22.04"


def _pool():
    return select(load_registry(RECIPES), OS)


def test_derive_seed_is_stable_and_independent():
    assert derive_seed(1, "a") == derive_seed(1, "a")
    assert derive_seed(1, "a") != derive_seed(2, "a")
    assert derive_seed(1, "a") != derive_seed(1, "b")


def test_token_param():
    value = generate_param(ParamSpec("f", "token", length=8), random.Random(0))
    assert len(value) == 8
    assert value.isalnum() and value.islower()


def test_build_seed_changes_values_but_not_the_chain():
    plan = generate(_pool(), OS, 3, 2, 0)
    chain = [s.recipe.id for s in plan.steps]

    one = materialize(plan, 1)
    two = materialize(plan, 2)

    assert [s.recipe.id for s in plan.steps] == chain
    assert one.values != two.values  # different flavour...
    assert one.values == materialize(plan, 1).values  # ...but reproducible


def test_plan_seed_reproduces_the_chain():
    a = generate(_pool(), OS, 3, 2, 7)
    b = generate(_pool(), OS, 3, 2, 7)
    assert [s.recipe.id for s in a.steps] == [s.recipe.id for s in b.steps]


def test_param_value_is_independent_of_chain_position():
    # A value depends on (build_seed, recipe, param), not on draw order or the
    # step's position, so the same recipe keeps its flavour across plans.
    pool = _pool()
    p1 = generate(pool, OS, 1, 1, 3)  # sudo step at index 1
    p2 = generate(pool, OS, 2, 1, 3)  # sudo step at index 2
    assert any(s.recipe.id == "sudo-misconfig-privesc" for s in p1.steps)
    assert any(s.recipe.id == "sudo-misconfig-privesc" for s in p2.steps)

    m1 = materialize(p1, 42)
    m2 = materialize(p2, 42)
    key = "sudo-misconfig-privesc.binary"
    assert m1.values[key] == m2.values[key]
