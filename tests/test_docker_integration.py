"""Real-Docker integration tests (opt-in).

    BOXES_DOCKER_TESTS=1 python3 -m pytest -m docker

These build/use the per-OS `boxes/base:<os>` images and are intentionally not
part of the default fast suite.
"""

import os
from pathlib import Path

import pytest

from boxes.backends import get_backend
from boxes import proxy as proxy_mod
from boxes.harness import check_recipe
from boxes.images import ensure_image, image_tag
from boxes.registry import load_registry
from boxes.runner import verify_recipe

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        os.environ.get("BOXES_DOCKER_TESTS") != "1",
        reason="set BOXES_DOCKER_TESTS=1 to run Docker integration tests",
    ),
]

RECIPES = Path(__file__).resolve().parents[1] / "recipes"
OSES = ["ubuntu-22.04", "debian-12", "ubuntu-24.04"]


@pytest.fixture(scope="module")
def backend():
    b = get_backend("docker")
    if not b.available():
        pytest.skip("docker daemon is not available")
    return b


VERIFIABLE = [r.id for r in load_registry(RECIPES) if r.verifiable and r.supports("container")]


@pytest.mark.parametrize("os_name", OSES)
@pytest.mark.parametrize("recipe_id", VERIFIABLE)
def test_recipe_verifies_in_a_real_container(backend, os_name, recipe_id):
    recipe = next(r for r in load_registry(RECIPES) if r.id == recipe_id)
    if not recipe.applies_to(os_name):
        pytest.skip(f"{recipe_id} does not apply to {os_name}")
    if recipe_id == "package-probe" and not proxy_mod.is_up():
        pytest.skip("provisioning proxy is not running (`boxes proxy up`)")
    assert ensure_image(backend, os_name).ok
    fixture = check_recipe(recipe, os_name=os_name).fixture
    result = verify_recipe(recipe, fixture, backend, image_tag(os_name))
    assert result.ok, [(s.phase, s.output) for s in result.steps]
