from pathlib import Path

import pytest

from boxes.recipe import load_recipe


def _write(tmp_path: Path, poc_block: str, extra: str = "", rid: str = "r"):
    d = tmp_path / "r"
    d.mkdir()
    (d / "provision.sh").write_text("echo provision\n")
    (d / "poc.sh").write_text("echo poc\n")
    (d / "recipe.yaml").write_text(
        f"id: {rid}\n"
        "version: 1.0.0\n"
        "kind: foothold\n"
        'os: ["ubuntu-*"]\n'
        "difficulty: 2\n"
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


def test_recipe_difficulty_is_a_numeric_level(tmp_path):
    r = _write(tmp_path, "poc:\n  context: attacker\n  container: ./poc.sh")
    assert r.difficulty == 2


def test_recipe_id_must_be_path_safe(tmp_path):
    with pytest.raises(ValueError, match="recipe id"):
        _write(
            tmp_path,
            "poc:\n  context: attacker\n  container: ./poc.sh",
            rid="../escape",
        )


def test_poc_cannot_escape_the_recipe_directory(tmp_path):
    (tmp_path / "outside.sh").write_text("echo outside\n")
    with pytest.raises(ValueError, match="inside the recipe"):
        _write(
            tmp_path,
            "poc:\n  context: attacker\n  container: ../outside.sh",
        )


def test_assets_cannot_escape_the_recipe_directory(tmp_path):
    with pytest.raises(ValueError, match="inside the recipe"):
        _write(
            tmp_path,
            "poc:\n  context: attacker\n  container: ./poc.sh",
            extra="assets: /etc",
        )


def test_empty_actor_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="actor must not be empty"):
        _write(
            tmp_path,
            "poc:\n  context: target\n  container: ./poc.sh",
            extra='actor: ""',
        )
