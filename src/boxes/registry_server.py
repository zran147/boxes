"""Reference read/write registry server.

GET serves the static signed index/bundles. POST /v1/publish accepts a signed
bundle (and optional attestation), verifies it, and updates the operator-signed
index. Without an operator key the server is read-only.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import json
import tempfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import attest, bundles, registry_client, signing
from .harness import check_recipe
from .lint import lint
from .recipe import load_recipe


class PublishError(ValueError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def publish(
    registry_dir: str | Path,
    operator_key: str | Path,
    payload: dict,
    trusted_publishers: set[str] | frozenset[str] | None = None,
) -> dict:
    try:
        bundle_b64 = payload["bundle"]
        publisher = str(payload["publisher"])
        publisher_key = str(payload["publisher_key"])
        signature = str(payload["signature"])
    except KeyError as e:
        raise PublishError(f"missing field: {e}") from e

    try:
        data = base64.b64decode(bundle_b64, validate=True)
    except Exception as e:  # noqa: BLE001
        raise PublishError(f"bad bundle encoding: {e}") from e

    with tempfile.TemporaryDirectory() as tmp:
        tar = Path(tmp) / "bundle.tar.gz"
        tar.write_bytes(data)
        try:
            manifest, files = bundles.read_bundle(tar)
        except ValueError as e:
            raise PublishError(f"invalid bundle: {e}") from e
        digest = bundles.bundle_hash(manifest)

        public = signing.public_from_pem(publisher_key)
        fingerprint = signing.fingerprint(public)
        if trusted_publishers and fingerprint not in trusted_publishers:
            raise PublishError("publisher key is not trusted", status=403)
        if not signing.verify(public, digest.encode("ascii"), signature):
            raise PublishError("bundle signature is invalid", status=403)
        if (
            manifest.get("id") != payload.get("id", manifest.get("id"))
            or manifest.get("version") != payload.get("version", manifest.get("version"))
            or manifest.get("publisher") != publisher
        ):
            raise PublishError("bundle metadata does not match the request")

        raw_attestations = payload.get("attestations")
        if raw_attestations is None and payload.get("attestation") is not None:
            raw_attestations = [payload["attestation"]]
        attestations = list(raw_attestations or [])
        for attestation in attestations:
            ok, error = attest.verify(attestation)
            if not ok:
                raise PublishError(f"attestation: {error}", status=403)
            if attestation.get("signer_fingerprint") != fingerprint:
                raise PublishError("attestation signer is not the publisher", status=403)
            if (
                attestation.get("recipe") != manifest["id"]
                or attestation.get("version") != manifest["version"]
                or attestation.get("files") != manifest["files"]
                or attestation.get("result") != "pass"
            ):
                raise PublishError("attestation does not match the bundle", status=403)

        # Server-side symbolic preflight; execution evidence is the attestation.
        extract = Path(tmp) / "recipe"
        bundles.extract_bundle(tar, extract, expected_bundle=digest)
        try:
            recipe = load_recipe(extract / "recipe.yaml")
        except ValueError as e:
            raise PublishError(f"recipe does not load: {e}") from e
        errors = lint([recipe])
        if not recipe.verifiable:
            errors.append(f"{recipe.id}: registry recipes need provision+poc")
        os_name = None
        if attestations:
            os_name = attestations[0].get("os")
        checked = check_recipe(recipe, os_name=os_name)
        errors.extend(checked.errors)
        if errors:
            raise PublishError("recipe failed preflight: " + "; ".join(errors))

    directory = Path(registry_dir)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "bundles").mkdir(exist_ok=True)
    target = directory / "bundles" / f"{digest}.tar.gz"
    target.write_bytes(data)

    operator_private = signing.load_private(operator_key)
    operator_public = operator_private.public_key()
    index_path = directory / "index.json"
    if index_path.is_file():
        index = json.loads(index_path.read_text())
        index_signature = index.pop("signature", None)
        if not index_signature or not signing.verify_json(
            operator_public, index, index_signature
        ):
            raise PublishError("existing index was not signed by this operator key", 403)
        sequence = int(index.get("sequence", 0)) + 1
        entries = list(index.get("recipes", []))
        revoked_publishers = list(index.get("revoked_publishers", []))
        revoked_bundles = list(index.get("revoked_bundles", []))
    else:
        sequence = 1
        entries = []
        revoked_publishers = []
        revoked_bundles = []

    new_entry = {
        "id": recipe.id,
        "version": recipe.version,
        "publisher": publisher,
        "publisher_key": signing.public_pem(public),
        "publisher_fingerprint": fingerprint,
        "bundle": digest,
        "bundle_signature": signature,
        "files": manifest["files"],
        "attestations": attestations,
        "attestation": attestations[0] if attestations else None,
        "bundle_url": f"bundles/{digest}.tar.gz",
        "tar_sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "metadata": {
            "description": recipe.description,
            "os": recipe.os,
            "difficulty": recipe.difficulty,
            "tools": recipe.tools or [],
            "poc_backend": recipe.poc_backend,
        },
    }

    same = [
        entry for entry in entries
        if entry.get("id") == recipe.id and entry.get("version") == recipe.version
    ]
    if same:
        if any(entry.get("bundle") != digest for entry in same):
            raise PublishError(
                f"{recipe.id}@{recipe.version} already exists with different content",
                status=409,
            )
        for entry in same:
            entry["attestations"] = attestations
            entry["attestation"] = attestations[0] if attestations else None
    else:
        entries.append(new_entry)
    entries.sort(key=lambda entry: (entry["id"], registry_client._version_key(entry["version"])))

    body = {
        "schema": registry_client.REGISTRY_SCHEMA,
        "sequence": sequence,
        "generated_at": registry_client._now(),
        "expires_at": registry_client._expiry(),
        "revoked_publishers": revoked_publishers,
        "revoked_bundles": revoked_bundles,
        "operator": signing.fingerprint(operator_public),
        "recipes": entries,
    }
    body["signature"] = signing.sign_json(operator_private, body)
    registry_client._write_json(index_path, body)
    return {"sequence": sequence, "entry": new_entry}


class RegistryHandler(SimpleHTTPRequestHandler):
    server_version = "boxes-registry/1"

    def _json(self, status: int, value: dict) -> None:
        data = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802 - stdlib name
        if self.path.rstrip("/") != "/v1/publish":
            self._json(404, {"error": "not found"})
            return
        if self.server.operator_key is None:
            self._json(403, {"error": "registry is read-only"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 64 * 1024 * 1024:
                raise PublishError("invalid request size")
            payload = json.loads(self.rfile.read(length))
            result = publish(
                self.server.registry_dir,
                self.server.operator_key,
                payload,
                self.server.trusted_publishers,
            )
        except PublishError as e:
            self._json(e.status, {"error": str(e)})
        except Exception as e:  # noqa: BLE001
            self._json(400, {"error": str(e)})
        else:
            self._json(200, result)


def serve(
    directory: str | Path,
    bind: str,
    port: int,
    operator_key: str | Path | None = None,
    trusted_publishers: set[str] | None = None,
) -> None:
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    handler = functools.partial(RegistryHandler, directory=str(directory))
    server = ThreadingHTTPServer((bind, port), handler)
    server.registry_dir = directory
    server.operator_key = operator_key
    server.trusted_publishers = trusted_publishers
    try:
        server.serve_forever()
    finally:
        server.server_close()
