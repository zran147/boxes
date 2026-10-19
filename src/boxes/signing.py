"""Ed25519 signing helpers for registry metadata and bundles."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class SignatureError(ValueError):
    pass


def canonical_json(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def keygen(out: Path) -> dict:
    """Write <out>.key and <out>.pub; return fingerprints and paths."""
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = private.public_key()
    public_pem_bytes = public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path = Path(str(out) + ".key")
    public_path = Path(str(out) + ".pub")
    private_path.write_bytes(private_pem)
    private_path.chmod(0o600)
    public_path.write_bytes(public_pem_bytes)
    return {
        "private": private_path,
        "public": public_path,
        "fingerprint": fingerprint(public),
    }


def load_private(path: str | Path) -> Ed25519PrivateKey:
    data = Path(path).read_bytes()
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except ValueError as e:
        raise SignatureError(f"cannot load private key {path}: {e}") from e
    if not isinstance(key, Ed25519PrivateKey):
        raise SignatureError(f"{path} is not an Ed25519 private key")
    return key


def public_from_pem(pem: str | bytes) -> Ed25519PublicKey:
    data = pem.encode("utf-8") if isinstance(pem, str) else pem
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError:
        try:
            raw = base64.b64decode(data)
            key = Ed25519PublicKey.from_public_bytes(raw)
        except Exception as e:  # noqa: BLE001 - normalize bad key material
            raise SignatureError(f"cannot load public key: {e}") from e
    if not isinstance(key, Ed25519PublicKey):
        raise SignatureError("public key is not Ed25519")
    return key


def load_public(path: str | Path) -> Ed25519PublicKey:
    return public_from_pem(Path(path).read_bytes())


def public_pem(public: Ed25519PublicKey) -> str:
    return public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def public_raw(public: Ed25519PublicKey) -> bytes:
    return public.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def fingerprint(public: Ed25519PublicKey) -> str:
    return hashlib.sha256(public_raw(public)).hexdigest()


def sign(private: Ed25519PrivateKey, data: bytes) -> str:
    return base64.b64encode(private.sign(data)).decode("ascii")


def verify(public: Ed25519PublicKey, data: bytes, signature: str) -> bool:
    try:
        public.verify(base64.b64decode(signature), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def sign_json(private: Ed25519PrivateKey, value) -> str:
    return sign(private, canonical_json(value))


def verify_json(public: Ed25519PublicKey, value, signature: str) -> bool:
    return verify(public, canonical_json(value), signature)
