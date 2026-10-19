import functools
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from boxes import attest, registry_client, registry_server, signing
from boxes.recipe import load_recipe
from boxes.runner import StepResult, VerifyResult

RECIPES = Path(__file__).resolve().parents[1] / "recipes"


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("BOXES_CONFIG_FILE", str(tmp_path / "config.json"))
    monkeypatch.setenv("BOXES_REGISTRY_DIR", str(tmp_path / "installed"))
    monkeypatch.setenv("BOXES_LOCKFILE", str(tmp_path / "boxes.lock"))

    keys = signing.keygen(tmp_path / "keys" / "dev")
    source = tmp_path / "src" / "api-test"
    shutil.copytree(RECIPES / "web-env-leak-creds", source)
    recipe_yaml = source / "recipe.yaml"
    recipe_yaml.write_text(
        recipe_yaml.read_text().replace("id: web-env-leak-creds", "id: api-test")
    )

    registry = tmp_path / "registry"
    registry.mkdir()
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        functools.partial(registry_server.RegistryHandler, directory=str(registry)),
    )
    server.registry_dir = registry
    server.operator_key = keys["private"]
    server.trusted_publishers = None
    server.registry_lock = threading.Lock()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        yield SimpleNamespace(
            tmp_path=tmp_path,
            source=source,
            registry=registry,
            keys=keys,
            server=server,
            url=url,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _attestation(source: Path, key: Path, out: Path) -> Path:
    recipe = load_recipe(source / "recipe.yaml")
    result = VerifyResult(label=recipe.id)
    result.add(StepResult(recipe.id, "provision", True, 0, ""))
    result.add(StepResult(recipe.id, "poc", True, 0, ""))
    body = attest.build(
        recipe, result, image_id="img", os_name="ubuntu-22.04",
        backend="container", sandbox="locked",
        started_at="a", finished_at="b",
    )
    return attest.write(attest.sign(body, key), out)


def test_api_publish_add_install_verify(api):
    attestation = _attestation(api.source, api.keys["private"], api.tmp_path / "att")
    result = registry_client.publish_api(
        api.url, api.source, "tester", api.keys["private"], attestation
    )
    assert result["sequence"] == 1

    registry_client.add_registry("api", api.url, api.keys["public"])
    assert registry_client.search("api-test")[0]["id"] == "api-test"
    entry = registry_client.install("api-test")
    assert entry["attestation"]["sandbox"] == "locked"
    checked = registry_client.verify_installed()
    assert checked[0]["errors"] == []
    assert checked[0]["attested"] is True


def test_api_is_read_only_without_operator_key(api):
    api.server.operator_key = None
    attestation = _attestation(api.source, api.keys["private"], api.tmp_path / "att")
    with pytest.raises(registry_client.RegistryError, match="403"):
        registry_client.publish_api(
            api.url, api.source, "tester", api.keys["private"], attestation
        )


def test_api_rejects_an_untrusted_publisher(api):
    other = signing.keygen(api.tmp_path / "keys" / "other")
    api.server.trusted_publishers = {
        signing.fingerprint(signing.load_public(other["public"]))
    }
    attestation = _attestation(api.source, api.keys["private"], api.tmp_path / "att")
    with pytest.raises(registry_client.RegistryError, match="403"):
        registry_client.publish_api(
            api.url, api.source, "tester", api.keys["private"], attestation
        )


def test_concurrent_publishes_keep_both_entries(api):
    source2 = api.tmp_path / "src" / "api-test-2"
    shutil.copytree(RECIPES / "web-env-leak-creds", source2)
    yaml = source2 / "recipe.yaml"
    yaml.write_text(yaml.read_text().replace("id: web-env-leak-creds", "id: api-test-2"))
    att1 = _attestation(api.source, api.keys["private"], api.tmp_path / "a1")
    att2 = _attestation(source2, api.keys["private"], api.tmp_path / "a2")

    def one(source, att):
        return registry_client.publish_api(
            api.url, source, "tester", api.keys["private"], att
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda args: one(*args), [(api.source, att1), (source2, att2)]))

    registry_client.add_registry("api", api.url, api.keys["public"])
    index = registry_client.fetch_index(
        registry_client.load_config()["registries"]["api"]
    )
    ids = {entry["id"] for entry in index["recipes"]}
    assert ids == {"api-test", "api-test-2"}
    assert index["sequence"] == 2
