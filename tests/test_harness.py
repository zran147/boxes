from pathlib import Path

from boxes.facts import parse_fact
from boxes.harness import SAMPLE_OS, check_recipe
from boxes.recipe import ParamSpec, Recipe
from boxes.registry import load_registry

RECIPES = Path(__file__).resolve().parents[1] / "recipes"


def test_all_shipped_recipes_pass_harness():
    for r in load_registry(RECIPES):
        res = check_recipe(r)
        assert res.ok, f"{r.id}: {res.errors}"
        assert res.fixture is not None


def test_fixture_is_fully_grounded():
    for r in load_registry(RECIPES):
        fx = check_recipe(r).fixture
        assert fx.os == SAMPLE_OS
        assert "$" not in " ".join(fx.requires + fx.provides)
        assert "{" not in fx.walkthrough
        for name in r.params:
            assert name in fx.params


def test_unresolved_walkthrough_placeholder_is_caught():
    r = Recipe(
        id="bad-placeholder",
        version="1.0.0",
        kind="discovery",
        os=["ubuntu-*"],
        difficulty=2,
        requires=[parse_fact("open_port($h, 80)")],
        provides=[parse_fact("knows(path, $v)")],
        yields=[],
        params={"v": ParamSpec("v", "choice", ["/x"])},
        walkthrough="we found {nope}",
    )
    res = check_recipe(r)
    assert not res.ok
    assert any("unresolved placeholder" in e for e in res.errors)


def test_os_mismatch_is_caught():
    r = Recipe(
        id="wrong-os",
        version="1.0.0",
        kind="discovery",
        os=["windows-*"],
        difficulty=2,
        requires=[parse_fact("open_port($h, 80)")],
        provides=[parse_fact("knows(path, $v)")],
        yields=[],
        params={"v": ParamSpec("v", "choice", ["/x"])},
        walkthrough="ok",
    )
    res = check_recipe(r)
    assert not res.ok
    assert any("matches none of the sample OSes" in e for e in res.errors)


def test_harness_picks_a_matching_sample_os():
    # A debian-only recipe should be tested against debian, not hard-fail on ubuntu.
    r = Recipe(
        id="debian-only",
        version="1.0.0",
        kind="discovery",
        os=["debian-*"],
        difficulty=2,
        requires=[parse_fact("open_port($h, 80)")],
        provides=[parse_fact("knows(path, $v)")],
        yields=[],
        params={"v": ParamSpec("v", "choice", ["/x"])},
        walkthrough="ok",
    )
    res = check_recipe(r)
    assert res.ok, res.errors
    assert res.fixture.os == "debian-12"


def test_ineffective_guard_is_caught():
    # requires two facts; dropping one should make it inapplicable. Here the
    # second requirement is redundant with the first, so the negative test
    # should notice the guard does nothing.
    r = Recipe(
        id="redundant-guard",
        version="1.0.0",
        kind="privesc",
        os=["ubuntu-*"],
        difficulty=2,
        requires=[parse_fact("access_shell($u)"), parse_fact("access_shell($u)")],
        provides=[parse_fact("access_root()")],
        yields=["root"],
        params={},
        walkthrough="ok",
    )
    res = check_recipe(r)
    assert any("still applies without" in e for e in res.errors)


def test_explicit_os_is_used_for_the_fixture():
    r = next(r for r in load_registry(RECIPES) if r.applies_to("debian-12"))
    res = check_recipe(r, os_name="debian-12")
    assert res.ok, res.errors
    assert res.fixture.os == "debian-12"
