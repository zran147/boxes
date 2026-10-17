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


def test_plan_variables_are_numbered_per_step():
    plan = generate(_pool(), OS, 3, 2, 0)
    assert [s.instance for s in plan.steps] == [
        f"{s.recipe.id}#{i}" for i, s in enumerate(plan.steps)
    ]

    manifest = materialize(plan, 5)
    instances = {s.instance for s in plan.steps}
    for key in manifest.values:
        if "." in key:
            prefix = key.split(".", 1)[0]
            assert "#" in prefix
            assert prefix in instances
