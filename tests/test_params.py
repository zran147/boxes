import random
import re

import pytest

from boxes.manifest import generate_param
from boxes.recipe import ParamSpec

_USER = re.compile(r"^[a-z][a-z0-9_]{1,31}$")
_RESERVED = {"root", "ubuntu", "boxes", "attacker", "www-data"}


def test_typed_int_respects_range_and_step():
    spec = ParamSpec("n", "int", min=10, max=20, step=5)
    values = {generate_param(spec, random.Random(seed)) for seed in range(50)}
    assert values <= {10, 15, 20}
    assert len(values) > 1


def test_typed_bool_and_weighted_typed_choice():
    bools = {
        generate_param(ParamSpec("b", "bool"), random.Random(seed)) for seed in range(20)
    }
    assert bools == {True, False}

    spec = ParamSpec("port", "choice", values=[80, 443], weights=[1.0, 10.0])
    values = [generate_param(spec, random.Random(seed)) for seed in range(100)]
    assert set(values) <= {80, 443}
    assert values.count(443) > values.count(80)


def test_username_is_deterministic_human_and_unique():
    spec = ParamSpec("u", "username")
    used = set()
    names = [generate_param(spec, random.Random(seed), used) for seed in range(20)]
    assert len(set(names)) == len(names)
    for name in names:
        assert _USER.match(name)
        assert name not in _RESERVED

    again = generate_param(spec, random.Random(0), used_users=set())
    assert again == names[0]


def test_username_service_style():
    spec = ParamSpec("u", "username", styles=["svc_role"])
    names = {generate_param(spec, random.Random(seed)) for seed in range(10)}
    assert all(name.startswith("svc_") for name in names)


def test_username_rejects_unknown_style_via_loader(tmp_path):
    from boxes.recipe import load_recipe

    d = tmp_path / "r"
    d.mkdir()
    (d / "provision.sh").write_text("true\n")
    (d / "poc.sh").write_text("true\n")
    (d / "recipe.yaml").write_text(
        "id: r\n"
        "version: 1.0.0\n"
        "kind: discovery\n"
        'os: ["ubuntu-*"]\n'
        "difficulty: 2\n"
        "requires: ['open_port($h, 80)']\n"
        "provides: ['knows(a, $u)']\n"
        "params:\n"
        "  u:\n"
        "    type: username\n"
        '    styles: ["moon"]\n'
        "tools: [curl, ssh]\n"
        "provision: ./provision.sh\n"
        "poc:\n  context: target\n  container: ./poc.sh\n"
        "walkthrough: hi\n"
    )
    with pytest.raises(ValueError, match="unknown style"):
        load_recipe(d / "recipe.yaml")


def test_loader_accepts_typed_params(tmp_path):
    from boxes.recipe import load_recipe

    d = tmp_path / "typed"
    d.mkdir()
    (d / "provision.sh").write_text("true\n")
    (d / "poc.sh").write_text("true\n")
    (d / "recipe.yaml").write_text(
        "id: typed\n"
        "version: 1.0.0\n"
        "kind: discovery\n"
        'os: ["ubuntu-*"]\n'
        "difficulty: 2\n"
        "requires: ['open_port($h, 80)']\n"
        "provides: ['knows(a, $u)']\n"
        "params:\n"
        "  u:\n"
        "    type: username\n"
        "  n:\n"
        "    type: int\n"
        "    min: 1\n"
        "    max: 9\n"
        "    step: 2\n"
        "  b:\n"
        "    type: bool\n"
        "  c:\n"
        "    type: choice\n"
        "    values: [80, 443]\n"
        "    weights: [1, 3]\n"
        "tools: [curl, ssh]\n"
        "provision: ./provision.sh\n"
        "poc:\n  context: target\n  container: ./poc.sh\n"
        "walkthrough: hi\n"
    )
    r = load_recipe(d / "recipe.yaml")
    assert r.difficulty == 2
    assert r.params["u"].type == "username"
    assert r.params["n"].min == 1 and r.params["n"].max == 9 and r.params["n"].step == 2
    assert r.params["b"].type == "bool"
    assert r.params["c"].values == [80, 443]
    assert r.params["c"].weights == [1.0, 3.0]
    assert r.tools == ["curl", "ssh"]
