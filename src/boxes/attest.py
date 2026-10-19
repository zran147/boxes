"""Signed verification attestations.

An attestation records what was verified (recipe files, OS, backend, sandbox,
image, toolkit) and is signed by the CI/publisher key. It is evidence, not a
substitute for the sandbox.
"""

from __future__ import annotations

import hashlib
import socket
from pathlib import Path

from . import toolkit
from .bundles import file_hashes
from .signing import (
    canonical_json,
    fingerprint,
    load_private,
    public_from_pem,
    public_pem,
    sign_json,
    verify_json,
)

SCHEMA = 1


def toolkit_hash() -> str:
    digest = hashlib.sha256()
    paths = [
        ("tools.yaml", toolkit.MANIFEST),
        ("tools.txt", toolkit.CONTEXT / "tools.txt"),
        ("pip.txt", toolkit.CONTEXT / "pip.txt"),
    ]
    for name, path in paths:
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        if path.is_file():
            digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def build(
    recipe,
    result,
    *,
    image_id: str,
    os_name: str,
    backend: str,
    sandbox: str,
    apt_snapshot: str | None = None,
    started_at: str,
    finished_at: str,
) -> dict:
    return {
        "schema": SCHEMA,
        "recipe": recipe.id,
        "version": recipe.version,
        "files": file_hashes(recipe.dir),
        "result": "pass" if result.ok else "fail",
        "steps": [
            {
                "phase": step.phase,
                "ok": step.ok,
                "exit_code": step.exit_code,
                "actor": step.actor,
            }
            for step in result.steps
        ],
        "os": os_name,
        "backend": backend,
        "sandbox": sandbox,
        "image": image_id,
        "apt_snapshot": apt_snapshot,
        "toolkit": toolkit_hash(),
        "runner": socket.gethostname(),
        "started_at": started_at,
        "finished_at": finished_at,
    }


def sign(body: dict, private_key: str | Path) -> dict:
    private = load_private(private_key)
    public = private.public_key()
    attestation = {
        **body,
        "signer": public_pem(public),
        "signer_fingerprint": fingerprint(public),
    }
    attestation["signature"] = sign_json(private, attestation)
    return attestation


def verify(attestation: dict) -> tuple[bool, str | None]:
    if not isinstance(attestation, dict):
        return False, "attestation is not an object"
    signature = attestation.get("signature")
    signer = attestation.get("signer")
    expected = attestation.get("signer_fingerprint")
    if not signature or not signer or not expected:
        return False, "attestation is missing signer or signature"
    try:
        public = public_from_pem(signer)
    except Exception as e:  # noqa: BLE001
        return False, f"bad attestation signer: {e}"
    if fingerprint(public) != expected:
        return False, "attestation signer fingerprint mismatch"
    body = {key: value for key, value in attestation.items() if key != "signature"}
    if not verify_json(public, body, signature):
        return False, "attestation signature is invalid"
    return True, None


def write(attestation: dict, directory: str | Path) -> Path:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    parts = [
        str(attestation.get(key))
        for key in ("recipe", "version", "os", "backend", "sandbox")
    ]
    if any(
        not part or "/" in part or "\\" in part or part in {".", ".."}
        for part in parts
    ):
        raise ValueError(f"unsafe attestation filename component(s): {parts!r}")
    name = "-".join(parts)
    path = directory / f"{name}.json"
    path.write_text(canonical_json(attestation).decode("utf-8") + "\n")
    return path
