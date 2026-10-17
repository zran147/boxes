"""Real-Docker integration tests (opt-in).

    BOXES_DOCKER_TESTS=1 python3 -m pytest -m docker

These build/use the `boxes/base:ubuntu-22.04` image and are intentionally not
part of the default fast suite.
"""

import os
from pathlib import Path

import pytest

from boxes.backends import get_backend
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


@pytest.fixture(scope="module")
def backend():
    b = get_backend("docker")
    if not b.available():
        pytest.skip("docker daemon is not available")
    assert ensure_image(b, "ubuntu-22.04").ok
    return b


VERIFIABLE = [r.id for r in load_registry(RECIPES) if r.verifiable]


@pytest.mark.parametrize("recipe_id", VERIFIABLE)
def test_recipe_verifies_in_a_real_container(backend, recipe_id):
    recipe = next(r for r in load_registry(RECIPES) if r.id == recipe_id)
    fixture = check_recipe(recipe).fixture
    result = verify_recipe(recipe, fixture, backend, image_tag("ubuntu-22.04"))
    assert result.ok, [(s.phase, s.output) for s in result.steps]
