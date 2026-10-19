import copy

import pytest

from boxes import attest, signing
from boxes.recipe import load_recipe
from boxes.runner import StepResult, VerifyResult

from pathlib import Path

RECIPES = Path(__file__).resolve().parents[1] / "recipes"


def _result(recipe_id: str) -> VerifyResult:
    result = VerifyResult(label=recipe_id)
    result.add(StepResult(recipe_id, "provision", True, 0, ""))
    result.add(StepResult(recipe_id, "poc", True, 0, ""))
    return result


def test_build_sign_verify_attestation(tmp_path):
    recipe = load_recipe(RECIPES / "web-env-leak-creds" / "recipe.yaml")
    keys = signing.keygen(tmp_path / "keys" / "ci")
    body = attest.build(
        recipe,
        _result(recipe.id),
        image_id="sha256:image",
        os_name="ubuntu-22.04",
        backend="container",
        sandbox="locked",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:05+00:00",
    )
    signed = attest.sign(body, keys["private"])
    ok, error = attest.verify(signed)
    assert ok, error
    assert signed["sandbox"] == "locked"
    assert signed["result"] == "pass"
    assert signed["files"] == signed["files"]

    path = attest.write(signed, tmp_path / "attestations")
    assert path.is_file()

    tampered = copy.deepcopy(signed)
    tampered["result"] = "fail"
    ok, error = attest.verify(tampered)
    assert not ok
    assert "signature" in error


def test_attestation_filename_cannot_escape_the_directory(tmp_path):
    with pytest.raises(ValueError, match="unsafe"):
        attest.write(
            {
                "recipe": "../escape",
                "version": "1.0.0",
                "os": "ubuntu-22.04",
                "backend": "container",
                "sandbox": "locked",
            },
            tmp_path / "attestations",
        )


def test_attestation_signer_fingerprint_is_checked(tmp_path):
    recipe = load_recipe(RECIPES / "web-env-leak-creds" / "recipe.yaml")
    keys = signing.keygen(tmp_path / "keys" / "ci")
    body = attest.build(
        recipe, _result(recipe.id), image_id="img", os_name="ubuntu-22.04",
        backend="container", sandbox="locked",
        started_at="a", finished_at="b",
    )
    signed = attest.sign(body, keys["private"])
    signed["signer_fingerprint"] = "0" * 64
    ok, error = attest.verify(signed)
    assert not ok
    assert "fingerprint" in error
