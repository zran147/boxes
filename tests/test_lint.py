from pathlib import Path

from boxes.lint import lint
from boxes.recipe import ParamSpec, Recipe
from boxes.facts import parse_fact

RECIPES = Path(__file__).resolve().parents[1] / "recipes"


def _mk(**kw):
    base = dict(
        id="x",
        version="1.0.0",
        kind="discovery",
        os=["ubuntu-*"],
        difficulty=0.1,
        requires=[parse_fact("open_port($h, 80)")],
        provides=[parse_fact("knows(a, $v)")],
        yields=[],
        params={"v": ParamSpec("v", "choice", ["x"])},
        walkthrough="",
    )
    base.update(kw)
    return Recipe(**base)


def test_shipped_recipes_pass_lint():
    from boxes.registry import load_registry

    assert lint(load_registry(RECIPES)) == []


def test_root_flag_must_be_privesc():
    r = _mk(kind="discovery", yields=["root"], requires=[parse_fact("access_shell($u)")])
    errs = lint([r])
    assert any("must be 'privesc'" in e for e in errs)


def test_user_flag_must_be_foothold():
    r = _mk(kind="creds", yields=["user"], requires=[parse_fact("access_shell($u)")])
    errs = lint([r])
    assert any("must be 'foothold'" in e for e in errs)


def test_shortcut_privesc_rejected():
    # a privesc that reaches root straight from network exposure is a shortcut
    r = _mk(
        kind="privesc",
        yields=["root"],
        requires=[parse_fact("open_port($h, 22)")],
        provides=[parse_fact("access_root()")],
        params={},
    )
    errs = lint([r])
    assert any("only requires prelude facts" in e for e in errs)


def test_foothold_with_network_rce_is_allowed():
    # the RCE-in-one-step case the user asked for is legitimate
    r = _mk(
        kind="foothold",
        yields=["user"],
        requires=[parse_fact("open_port($h, 8080)")],
        provides=[parse_fact("access_shell($u)")],
        params={"u": ParamSpec("u", "choice", ["www-data"])},
    )
    assert lint([r]) == []


def test_unbound_provide_variable_rejected():
    r = _mk(provides=[parse_fact("knows(a, $nope)")], params={})
    errs = lint([r])
    assert any("$nope" in e for e in errs)


def test_cannot_yield_both_flags():
    r = _mk(kind="privesc", yields=["user", "root"], requires=[parse_fact("access_shell($u)")])
    errs = lint([r])
    assert any("both the user and root" in e for e in errs)


def test_actor_must_be_bound():
    r = _mk(actor="$nope")
    errs = lint([r])
    assert any("actor $nope" in e for e in errs)


def test_open_port_must_be_concrete():
    r = _mk(requires=[parse_fact("open_port($h, $p)")])
    errs = lint([r])
    assert any("concrete integer port" in e for e in errs)


def test_poc_context_is_validated():
    r = _mk(poc_context="moon")
    errs = lint([r])
    assert any("poc.context" in e for e in errs)
