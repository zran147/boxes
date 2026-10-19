import shutil
from pathlib import Path

import pytest

from boxes import bundles
from boxes.recipe import load_recipe

RECIPES = Path(__file__).resolve().parents[1] / "recipes"


def _source(tmp_path):
    source = tmp_path / "src" / "bundle-test"
    shutil.copytree(RECIPES / "web-env-leak-creds", source)
    yaml = source / "recipe.yaml"
    yaml.write_text(yaml.read_text().replace("id: web-env-leak-creds", "id: bundle-test"))
    return source


def test_bundle_is_deterministic_and_verifiable(tmp_path):
    source = _source(tmp_path)
    one = tmp_path / "one.tar.gz"
    two = tmp_path / "two.tar.gz"
    m1, b1, t1 = bundles.build_bundle(source, "tester", one)
    m2, b2, t2 = bundles.build_bundle(source, "tester", two)
    assert b1 == b2
    assert t1 == t2
    assert one.read_bytes() == two.read_bytes()

    manifest, files = bundles.read_bundle(one)
    assert manifest["id"] == "bundle-test"
    assert manifest["files"] == bundles.file_hashes(source)

    dest = tmp_path / "extracted"
    bundles.extract_bundle(one, dest, expected_bundle=b1)
    recipe = load_recipe(dest / "recipe.yaml")
    assert recipe.id == "bundle-test"
    assert (dest / "provision.sh").is_file()


def test_bundle_rejects_a_tampered_file(tmp_path):
    source = _source(tmp_path)
    path = tmp_path / "bundle.tar.gz"
    bundles.build_bundle(source, "tester", path)

    with pytest.raises(ValueError, match="hash mismatch|do not match"):
        # Rebuild the tar with a changed file but the old manifest.
        import io
        import tarfile

        manifest, files = bundles.read_bundle(path)
        files["poc.sh"] = b"# changed\n"
        with tarfile.open(path, "w:gz") as tar:
            for name, data in sorted({**files, "bundle.json": bundles.canonical_json(manifest)}.items()):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        bundles.read_bundle(path)
