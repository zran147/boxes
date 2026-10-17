from pathlib import Path

import pytest

from boxes.recipe import load_recipe


def _write(tmp_path: Path, poc_block: str):
    d = tmp_path / "r"
    d.mkdir()
    (d / "provision.sh").write_text("echo provision\n")
    (d / "poc.sh").write_text("echo poc\n")
    (d / "recipe.yaml").write_text(
        "id: r\n"
        "version: 1.0.0\n"
        "kind: foothold\n"
        'os: ["ubuntu-*"]\n'
        "difficulty: 0.1\n"
        'yields: ["user"]\n'
        "requires:\n"
        "  - open_port($h, 22)\n"
        "provides:\n"
        "  - access_shell($u)\n"
        "params:\n"
        "  u:\n"
        "    type: choice\n"
        '    values: ["alice"]\n'
        "provision: ./provision.sh\n"
        f"{poc_block}\n"
        "walkthrough: |\n"
        "  hi\n"
    )
    return load_recipe(d / "recipe.yaml")


def test_poc_mapping_with_context(tmp_path):
    r = _write(tmp_path, "poc:\n  script: ./poc.sh\n  context: attacker")
    assert r.poc == "./poc.sh"
    assert r.poc_context == "attacker"


def test_flat_poc_defaults_to_target_context(tmp_path):
    r = _write(tmp_path, "poc: ./poc.sh")
    assert r.poc_context == "target"


def test_invalid_poc_context_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        _write(tmp_path, "poc:\n  script: ./poc.sh\n  context: moon")


def test_poc_mapping_requires_script(tmp_path):
    with pytest.raises(ValueError):
        _write(tmp_path, "poc:\n  context: attacker")


def test_poc_variants_enable_both_backends(tmp_path):
    r = _write(
        tmp_path,
        "poc:\n  context: attacker\n  container: ./poc.sh\n  vm: ./poc.sh",
    )
    assert r.supports("container")
    assert r.supports("vm")
    assert r.script("poc", "container").name == "poc.sh"
    assert r.script("poc", "vm").name == "poc.sh"


def test_vm_only_poc_does_not_support_container(tmp_path):
    r = _write(tmp_path, "poc:\n  context: attacker\n  vm: ./poc.sh")
    assert r.supports("vm")
    assert not r.supports("container")
    assert r.script("poc", "vm").name == "poc.sh"
