from pathlib import Path

import pytest

from boxes.recipe import load_recipe


def _write(tmp_path: Path, poc_block: str, extra: str = ""):
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
        f"{extra}\n"
        "walkthrough: |\n"
        "  hi\n"
    )
    return load_recipe(d / "recipe.yaml")


def test_container_poc(tmp_path):
    r = _write(tmp_path, "poc:\n  context: attacker\n  container: ./poc.sh")
    assert r.poc_backend == "container"
    assert r.poc == "./poc.sh"
    assert r.supports("container")
    # a container PoC is a portable proxy and may also run on the VM product
    assert r.supports("vm")


def test_vm_poc_is_vm_only(tmp_path):
    r = _write(tmp_path, "poc:\n  context: attacker\n  vm: ./poc.sh")
    assert r.poc_backend == "vm"
    assert r.supports("vm")
    assert not r.supports("container")


def test_two_poc_keys_are_rejected(tmp_path):
    with pytest.raises(ValueError):
        _write(
            tmp_path,
            "poc:\n  context: attacker\n  container: ./poc.sh\n  vm: ./poc.sh",
        )


def test_missing_poc_key_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        _write(tmp_path, "poc:\n  context: attacker")


def test_fidelity_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        _write(
            tmp_path,
            "poc:\n  context: attacker\n  container: ./poc.sh",
            extra="fidelity: container",
        )


def test_invalid_poc_context_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        _write(tmp_path, "poc:\n  container: ./poc.sh\n  context: moon")


def test_numeric_difficulty_maps_to_a_band(tmp_path):
    r = _write(tmp_path, "poc:\n  context: attacker\n  container: ./poc.sh")
    assert r.difficulty == "easy"
