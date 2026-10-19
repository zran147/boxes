import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from boxes import registry_client, signing
from boxes.recipe import load_recipe

RECIPES = Path(__file__).resolve().parents[1] / "recipes"


@pytest.fixture
def reg(tmp_path, monkeypatch):
    monkeypatch.setenv("BOXES_CONFIG_FILE", str(tmp_path / "config.json"))
    monkeypatch.setenv("BOXES_REGISTRY_DIR", str(tmp_path / "installed"))
    monkeypatch.setenv("BOXES_LOCKFILE", str(tmp_path / "boxes.lock"))

    keys = signing.keygen(tmp_path / "keys" / "dev")
    source = tmp_path / "src" / "reg-test"
    shutil.copytree(RECIPES / "web-env-leak-creds", source)
    recipe_yaml = source / "recipe.yaml"
    recipe_yaml.write_text(
        recipe_yaml.read_text().replace("id: web-env-leak-creds", "id: reg-test")
    )

    registry = tmp_path / "registry"
    registry_client.publish(source, registry, "tester", keys["private"])
    old_index = (registry / "index.json").read_bytes()
    registry_client.add_registry("test", str(registry), keys["public"])
    return SimpleNamespace(
        tmp_path=tmp_path,
        source=source,
        registry=registry,
        keys=keys,
        old_index=old_index,
    )


def test_publish_add_search_install_verify(reg):
    results = registry_client.search("reg-test")
    assert len(results) == 1
    assert results[0]["id"] == "reg-test"
    assert results[0]["metadata"]["description"]

    entry = registry_client.install("reg-test")
    assert entry["version"] == "1.0.0"
    installed = registry_client.registry_recipes() / "reg-test"
    recipe = load_recipe(installed / "recipe.yaml")
    assert recipe.id == "reg-test"
    assert registry_client.is_registry_recipe(recipe)

    lock = registry_client.load_lock()
    assert lock["recipes"][0]["bundle"] == entry["bundle"]
    assert lock["registries"]["test"]["sequence"] == 1

    checks = registry_client.verify_installed()
    assert checks[0]["errors"] == []


def test_tampered_installed_file_is_repaired_with_force(reg):
    registry_client.install("reg-test")
    installed = registry_client.registry_recipes() / "reg-test"
    (installed / "poc.sh").write_text("# tampered\n")

    failed = registry_client.verify_installed()
    assert failed[0]["errors"]
    with pytest.raises(registry_client.RegistryError, match="files differ"):
        registry_client.install("reg-test")

    registry_client.install("reg-test", force=True)
    assert registry_client.verify_installed()[0]["errors"] == []


def test_tampered_index_is_rejected(reg):
    index_path = reg.registry / "index.json"
    index = json.loads(index_path.read_text())
    index["recipes"][0]["metadata"]["description"] = "tampered"
    index_path.write_text(json.dumps(index))

    with pytest.raises(registry_client.RegistryError, match="signature"):
        registry_client.search("reg-test")
    with pytest.raises(registry_client.RegistryError, match="signature"):
        registry_client.install("reg-test")


def test_tampered_bundle_is_rejected(reg):
    index = json.loads((reg.registry / "index.json").read_text())
    entry = index["recipes"][0]
    tar = reg.registry / entry["bundle_url"]
    tar.write_bytes(tar.read_bytes() + b"x")

    with pytest.raises(registry_client.RegistryError, match="checksum"):
        registry_client.install("reg-test")


def test_wrong_operator_key_is_rejected(reg):
    other = signing.keygen(reg.tmp_path / "keys" / "other")
    with pytest.raises(registry_client.RegistryError, match="signature"):
        registry_client.add_registry("other", str(reg.registry), other["public"])


def test_rollback_is_rejected(reg):
    registry_client.install("reg-test")
    # Move the source forward, publish sequence 2, and update the install.
    recipe_yaml = reg.source / "recipe.yaml"
    recipe_yaml.write_text(recipe_yaml.read_text().replace("version: 1.0.0", "version: 1.0.1"))
    registry_client.publish(reg.source, reg.registry, "tester", reg.keys["private"])
    changed = registry_client.update()
    assert [entry["version"] for entry in changed] == ["1.0.1"]

    # Replay the signed but older index.
    (reg.registry / "index.json").write_bytes(reg.old_index)
    with pytest.raises(registry_client.RegistryError, match="rollback"):
        registry_client.search("reg-test")
    with pytest.raises(registry_client.RegistryError, match="rollback"):
        registry_client.install("reg-test")

    checks = registry_client.verify_installed()
    assert checks and checks[0]["errors"]
    assert any("rollback" in error for error in checks[0]["errors"])


def test_update_installs_a_new_version(reg):
    installed = registry_client.install("reg-test")
    assert installed["version"] == "1.0.0"
    recipe_yaml = reg.source / "recipe.yaml"
    recipe_yaml.write_text(recipe_yaml.read_text().replace("version: 1.0.0", "version: 1.0.1"))
    registry_client.publish(reg.source, reg.registry, "tester", reg.keys["private"])
    changed = registry_client.update()
    assert [entry["version"] for entry in changed] == ["1.0.1"]
    assert registry_client.verify_installed()[0]["errors"] == []
    assert load_recipe(registry_client.registry_recipes() / "reg-test" / "recipe.yaml").version == "1.0.1"


def test_untrusted_guard(reg, capsys):
    from boxes.cli import _untrusted_check

    registry_client.install("reg-test")
    recipe = load_recipe(registry_client.registry_recipes() / "reg-test" / "recipe.yaml")

    args = SimpleNamespace(backend="docker", allow_untrusted=False)
    assert not _untrusted_check(args, [recipe])
    assert "Pass --allow-untrusted" in capsys.readouterr().err

    args.allow_untrusted = True
    assert _untrusted_check(args, [recipe])
    assert "warning" in capsys.readouterr().err

    args.backend = "qemu"
    assert not _untrusted_check(args, [recipe])
    assert "refusing QEMU" in capsys.readouterr().err

    args.backend = "docker"
    args.allow_untrusted = True
    args.sandbox = "trusted"
    assert not _untrusted_check(args, [recipe])
    assert "require the locked" in capsys.readouterr().err


def test_signing_roundtrip(tmp_path):
    keys = signing.keygen(tmp_path / "k")
    private = signing.load_private(keys["private"])
    public = signing.load_public(keys["public"])
    signature = signing.sign_json(private, {"hello": "world"})
    assert signing.verify_json(public, {"hello": "world"}, signature)
    assert not signing.verify_json(public, {"hello": "moon"}, signature)


def test_publish_and_install_with_attestation(reg, tmp_path):
    from boxes import attest, signing
    from boxes.recipe import load_recipe
    from boxes.runner import StepResult, VerifyResult

    recipe = load_recipe(reg.source / "recipe.yaml")
    result = VerifyResult(label=recipe.id)
    result.add(StepResult(recipe.id, "provision", True, 0, ""))
    result.add(StepResult(recipe.id, "poc", True, 0, ""))
    body = attest.build(
        recipe, result, image_id="img", os_name="ubuntu-22.04",
        backend="container", sandbox="locked",
        started_at="a", finished_at="b",
    )
    signed = attest.sign(body, reg.keys["private"])
    path = attest.write(signed, tmp_path / "att")
    registry_client.publish(
        reg.source, reg.registry, "tester", reg.keys["private"],
        attestation_path=path,
    )
    entry = registry_client.install("reg-test")
    assert entry["attestation"]["result"] == "pass"
    lock = registry_client.load_lock()
    assert lock["recipes"][0]["attestation"]
    checked = registry_client.verify_installed()
    assert checked[0]["errors"] == []
    assert checked[0]["attested"] is True


def test_attestation_must_match_bundle(reg, tmp_path):
    from boxes import attest
    from boxes.recipe import load_recipe
    from boxes.runner import StepResult, VerifyResult

    recipe = load_recipe(reg.source / "recipe.yaml")
    result = VerifyResult(label=recipe.id)
    result.add(StepResult(recipe.id, "provision", True, 0, ""))
    body = attest.build(
        recipe, result, image_id="img", os_name="ubuntu-22.04",
        backend="container", sandbox="locked",
        started_at="a", finished_at="b",
    )
    body["files"] = {}
    signed = attest.sign(body, reg.keys["private"])
    path = attest.write(signed, tmp_path / "att")
    with pytest.raises(registry_client.RegistryError, match="files"):
        registry_client.publish(
            reg.source, reg.registry, "tester", reg.keys["private"],
            attestation_path=path,
        )


def test_require_attestation(reg):
    with pytest.raises(registry_client.RegistryError, match="no attestation"):
        registry_client.install("reg-test", require_attestation=True)
