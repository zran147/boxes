import shutil
from pathlib import Path
from types import SimpleNamespace

from boxes import cli
from boxes.cli import main

RECIPES = Path(__file__).resolve().parents[1] / "recipes"


def test_multi_path_needs_at_least_two(capsys):
    assert main(["gen", "--multi-path", "1", "--to-user", "1", "--to-root", "1"]) == 2
    assert "at least 2" in capsys.readouterr().err


def test_multi_path_generates_multiple_paths(capsys):
    assert main([
        "gen", "--multi-path", "2", "--seed", "0", "--build-seed", "1",
        "--to-user", "3", "--to-root", "2",
    ]) == 0
    out = capsys.readouterr().out
    assert "## Path 1" in out
    assert "## Path 2" in out


def test_multi_path_requires_machine_on_verify(capsys):
    assert main(["verify", "--multi-path", "2", "--recipe", "x"]) == 2
    assert "only applies to --machine" in capsys.readouterr().err


def test_qemu_rejects_an_unsupported_os(capsys):
    rc = main(["verify", "--backend", "qemu", "--os", "rocky-9", "--recipe", "vm-kernel-probe"])
    assert rc == 2
    assert "unsupported VM OS" in capsys.readouterr().err


def test_qemu_image_rejects_an_unsupported_os(capsys):
    rc = main(["image", "build", "--backend", "qemu", "--os", "rocky-9"])
    assert rc == 2
    assert "unsupported VM OS" in capsys.readouterr().err


def test_gen_difficulty_filter(capsys):
    assert main([
        "gen", "--difficulty", "hard", "--to-user", "1", "--to-root", "1", "--seed", "0",
    ]) == 0
    out = capsys.readouterr().out
    assert "difficulty: **8/10 (hard)**" in out
    assert "user 8/10 (hard)" in out


def test_difficulty_requires_machine_on_verify(capsys):
    assert main(["verify", "--difficulty", "easy", "--recipe", "x"]) == 2
    assert "only apply to --machine" in capsys.readouterr().err


def test_image_tools_lists_the_attacker_toolkit(capsys):
    assert main(["image", "tools"]) == 0
    out = capsys.readouterr().out
    assert "nmap" in out
    assert "impacket-wmiexec" in out


def test_registry_keygen_cli(tmp_path, capsys):
    assert main(["registry", "keygen", "--out", str(tmp_path / "dev")]) == 0
    out = capsys.readouterr().out
    assert "fingerprint:" in out
    assert (tmp_path / "dev.key").is_file()
    assert (tmp_path / "dev.pub").is_file()


def test_registry_list_empty_cli(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("BOXES_CONFIG_FILE", str(tmp_path / "config.json"))
    monkeypatch.setenv("BOXES_LOCKFILE", str(tmp_path / "boxes.lock"))
    monkeypatch.setenv("BOXES_REGISTRY_DIR", str(tmp_path / "installed"))
    assert main(["registry", "list"]) == 0
    capsys.readouterr()


def test_attestation_requires_recipe_mode(capsys):
    assert main(["verify", "--machine", "--attest-key", "k"]) == 2
    assert "per recipe" in capsys.readouterr().err


def test_attestation_dir_requires_key(capsys):
    assert main(["verify", "--recipe", "x", "--attestation-dir", "a"]) == 2
    assert "requires --attest-key" in capsys.readouterr().err


def test_sandbox_isolated_is_qemu_only(capsys):
    assert main(["verify", "--backend", "docker", "--sandbox", "isolated", "--recipe", "x"]) == 2
    assert "QEMU-only" in capsys.readouterr().err


def test_locked_is_docker_only(capsys):
    assert main(["verify", "--backend", "qemu", "--sandbox", "locked", "--recipe", "x"]) == 2
    assert "Docker-only" in capsys.readouterr().err


def test_registry_only_project_loads_installed_recipes(tmp_path, monkeypatch):
    installed = tmp_path / "installed"
    shutil.copytree(
        RECIPES / "web-env-leak-creds", installed / "web-env-leak-creds"
    )
    monkeypatch.setenv("BOXES_REGISTRY_DIR", str(installed))
    args = SimpleNamespace(recipes=str(tmp_path / "missing-local-recipes"))
    recipes = cli._load_all_recipes(args)
    assert [recipe.id for recipe in recipes] == ["web-env-leak-creds"]


def test_missing_recipe_directories_are_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("BOXES_REGISTRY_DIR", str(tmp_path / "empty-installed"))
    args = SimpleNamespace(recipes=str(tmp_path / "missing-local-recipes"))
    import pytest

    with pytest.raises(FileNotFoundError):
        cli._load_all_recipes(args)


def test_new_refuses_an_installed_id(tmp_path, monkeypatch, capsys):
    installed = tmp_path / "installed"
    shutil.copytree(
        RECIPES / "web-env-leak-creds", installed / "web-env-leak-creds"
    )
    monkeypatch.setenv("BOXES_REGISTRY_DIR", str(installed))
    args = SimpleNamespace(
        recipes=str(tmp_path / "recipes"),
        id="web-env-leak-creds",
        kind="discovery",
        os=None,
        difficulty="medium",
        seed=0,
    )
    assert cli.cmd_new(args) == 2
    assert "installed registry" in capsys.readouterr().err
