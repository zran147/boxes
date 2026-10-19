"""Signed static registry client and publisher.

A registry is a directory (or HTTP prefix) containing a signed index.json and
content-addressed bundles/<sha256>.tar.gz files. The operator key trusts the
index; publisher keys inside the signed index trust individual bundles.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import attest
from .bundles import (
    SCHEMA as BUNDLE_SCHEMA,
    build_bundle,
    bundle_hash,
    extract_bundle,
    file_hashes,
)
from .harness import check_recipe
from .lint import lint
from .recipe import Recipe, load_recipe
from .signing import (
    SignatureError,
    canonical_json,
    fingerprint,
    load_private,
    load_public,
    public_from_pem,
    public_pem,
    sign,
    sign_json,
    verify,
    verify_json,
)

MAX_REF = 64 * 1024 * 1024
REGISTRY_SCHEMA = 1
INDEX_TTL_DAYS = 90


class RegistryError(RuntimeError):
    pass


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def registry_recipes() -> Path:
    return Path(os.environ.get("BOXES_REGISTRY_DIR", project_root() / ".boxes-registry" / "recipes"))


def lockfile() -> Path:
    return Path(os.environ.get("BOXES_LOCKFILE", project_root() / "boxes.lock"))


def config_file() -> Path:
    return Path(
        os.environ.get(
            "BOXES_CONFIG_FILE",
            Path(os.environ.get("BOXES_CONFIG_DIR", Path.home() / ".config" / "boxes"))
            / "registries.json",
        )
    )


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _expiry() -> str:
    return (
        datetime.now(timezone.utc) + timedelta(days=INDEX_TTL_DAYS)
    ).replace(microsecond=0).isoformat()


def _operator_keys(registry: dict) -> list[dict]:
    keys = registry.get("operator_keys")
    if keys:
        return list(keys)
    return [{
        "key": registry["operator_key"],
        "fingerprint": registry["operator_fingerprint"],
    }]


def _is_revoked(entry: dict, index: dict) -> bool:
    return (
        entry.get("publisher_fingerprint") in index.get("revoked_publishers", [])
        or entry.get("bundle") in index.get("revoked_bundles", [])
    )


def _read_json(path: Path, default):
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise RegistryError(f"cannot read {path}: {e}") from e


def _write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", text=True)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(value, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _normalize_url(url: str | Path) -> str:
    url = str(url)
    if url.startswith(("http://", "https://")):
        return url.rstrip("/")
    if url.startswith("file://"):
        return str(Path(url[7:]).expanduser().resolve())
    return str(Path(url).expanduser().resolve())


def read_ref(url: str, rel: str) -> bytes:
    if url.startswith(("http://", "https://")):
        full = url.rstrip("/") + "/" + rel.lstrip("/")
        try:
            with urllib.request.urlopen(full, timeout=60) as response:
                data = response.read(MAX_REF + 1)
        except OSError as e:
            raise RegistryError(f"cannot fetch {full}: {e}") from e
    else:
        full = str(Path(url) / rel)
        try:
            data = Path(full).read_bytes()
        except OSError as e:
            raise RegistryError(f"cannot read {full}: {e}") from e
    if len(data) > MAX_REF:
        raise RegistryError(f"{rel} is too large")
    return data


# --- registries/config ------------------------------------------------------


def load_config() -> dict:
    data = _read_json(config_file(), {"schema": 1, "registries": {}})
    data.setdefault("schema", 1)
    data.setdefault("registries", {})
    return data


def save_config(data: dict) -> None:
    _write_json(config_file(), data)


def load_lock() -> dict:
    data = _read_json(lockfile(), {"schema": 1, "registries": {}, "recipes": []})
    data.setdefault("schema", 1)
    data.setdefault("registries", {})
    data.setdefault("recipes", [])
    return data


def save_lock(data: dict) -> None:
    _write_json(lockfile(), data)


def add_registry(
    name: str, url: str | Path, key_paths: str | Path | list[str | Path]
) -> dict:
    if isinstance(key_paths, (str, Path)):
        key_paths = [key_paths]
    keys = []
    for key_path in key_paths:
        public = load_public(key_path)
        keys.append({
            "key": public_pem(public),
            "fingerprint": fingerprint(public),
        })
    if not keys:
        raise RegistryError("at least one operator key is required")
    reg = {
        "url": _normalize_url(url),
        "operator_keys": keys,
        "operator_key": keys[0]["key"],
        "operator_fingerprint": keys[0]["fingerprint"],
        "sequence": 0,
    }
    index = fetch_index(reg)
    reg["sequence"] = int(index["sequence"])
    config = load_config()
    config["registries"][name] = reg
    save_config(config)
    return reg


def remove_registry(name: str) -> None:
    config = load_config()
    if name not in config["registries"]:
        raise RegistryError(f"no such registry: {name}")
    del config["registries"][name]
    save_config(config)


def list_registries() -> list[dict]:
    config = load_config()
    return [
        {"name": name, **reg}
        for name, reg in sorted(config["registries"].items())
    ]


def _get_registry(name: str | None) -> tuple[str, dict]:
    config = load_config()
    registries = config.get("registries", {})
    if name is not None:
        if name not in registries:
            raise RegistryError(f"no such registry: {name}")
        return name, registries[name]
    if len(registries) == 1:
        return next(iter(registries.items()))
    if not registries:
        raise RegistryError("no registries configured; run `boxes registry add`")
    raise RegistryError("multiple registries configured; pass --registry")


# --- signed index -----------------------------------------------------------


def fetch_index(registry: dict, floor: int | None = None) -> dict:
    data = read_ref(registry["url"], "index.json")
    try:
        index = json.loads(data)
    except json.JSONDecodeError as e:
        raise RegistryError(f"invalid registry index: {e}") from e
    if not isinstance(index, dict) or index.get("schema") != REGISTRY_SCHEMA:
        raise RegistryError("unsupported registry index schema")
    signature = index.get("signature")
    if not signature:
        raise RegistryError("registry index is unsigned")
    body = dict(index)
    body.pop("signature", None)
    matched = None
    for item in _operator_keys(registry):
        try:
            public = public_from_pem(item["key"])
        except Exception:  # noqa: BLE001 - skip a malformed configured key
            continue
        if fingerprint(public) != item.get("fingerprint"):
            continue
        if verify_json(public, body, signature):
            matched = item
            break
    if matched is None:
        raise RegistryError("registry index signature is invalid for trusted operator keys")
    if index.get("operator") and index["operator"] != matched["fingerprint"]:
        raise RegistryError("registry index operator fingerprint mismatch")
    if index.get("expires_at"):
        try:
            expires = datetime.fromisoformat(index["expires_at"])
        except ValueError as e:
            raise RegistryError(f"invalid index expiry: {e}") from e
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < datetime.now(timezone.utc):
            raise RegistryError(f"registry index expired at {index['expires_at']}")
    for key in ("revoked_publishers", "revoked_bundles"):
        value = index.get(key, [])
        if not isinstance(value, list):
            raise RegistryError(f"registry index {key} must be a list")
    sequence = int(index.get("sequence", 0))
    if floor is not None and sequence < floor:
        raise RegistryError(
            f"registry index rollback: got sequence {sequence}, expected >= {floor}"
        )
    if not isinstance(index.get("recipes"), list):
        raise RegistryError("registry index has no recipes list")
    return index


# --- sequence/rollback state ------------------------------------------------


def _sequence_floor(name: str, registry: dict) -> int:
    floor = int(registry.get("sequence", 0))
    lock = load_lock()
    floor = max(
        floor,
        int(lock.get("registries", {}).get(name, {}).get("sequence", 0)),
    )
    return floor


def _remember_sequence(name: str, index: dict) -> None:
    sequence = int(index.get("sequence", 0))
    config = load_config()
    reg = config.get("registries", {}).get(name)
    if reg is not None and sequence > int(reg.get("sequence", 0)):
        reg["sequence"] = sequence
        save_config(config)
    lock = load_lock()
    reg_lock = lock.get("registries", {}).get(name)
    if reg_lock is not None and sequence > int(reg_lock.get("sequence", 0)):
        reg_lock["sequence"] = sequence
        save_lock(lock)


# --- resolution/install -----------------------------------------------------


def _version_key(version: str) -> tuple:
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError:
        return (0,)


def resolve(index: dict, spec: str) -> dict:
    if "@" in spec:
        rid, version = spec.rsplit("@", 1)
    else:
        rid, version = spec, None
    candidates = [
        entry for entry in index["recipes"]
        if entry.get("id") == rid and not _is_revoked(entry, index)
    ]
    if version is not None:
        candidates = [entry for entry in candidates if entry.get("version") == version]
    if not candidates:
        raise RegistryError(f"no recipe {spec!r} in registry (or it is revoked)")
    if version is None:
        top = max(candidates, key=lambda entry: _version_key(entry.get("version", "0")))
        candidates = [entry for entry in candidates if entry.get("version") == top["version"]]
    if len(candidates) != 1:
        raise RegistryError(f"recipe {spec!r} is ambiguous ({len(candidates)} entries)")
    return candidates[0]


def entry_attestations(entry: dict) -> list[dict]:
    attestations = entry.get("attestations")
    if attestations is not None:
        return list(attestations)
    single = entry.get("attestation")
    return [single] if single else []


def _entry_manifest(entry: dict) -> dict:
    return {
        "schema": BUNDLE_SCHEMA,
        "id": entry["id"],
        "version": entry["version"],
        "publisher": entry["publisher"],
        "files": entry["files"],
    }


def _verify_entry(entry: dict) -> None:
    public = public_from_pem(entry["publisher_key"])
    if fingerprint(public) != entry.get("publisher_fingerprint"):
        raise RegistryError("publisher key fingerprint mismatch")
    if not verify(public, entry["bundle"].encode("ascii"), entry["bundle_signature"]):
        raise RegistryError("bundle signature is invalid")
    manifest = _entry_manifest(entry)
    if bundle_hash(manifest) != entry["bundle"]:
        raise RegistryError("bundle hash does not match the manifest")


def install(
    spec: str,
    registry_name: str | None = None,
    force: bool = False,
    require_attestation: bool = False,
) -> dict:
    name, reg = _get_registry(registry_name)
    lock = load_lock()
    index = fetch_index(reg, floor=_sequence_floor(name, reg))
    _remember_sequence(name, index)
    entry = resolve(index, spec)
    _verify_entry(entry)
    if require_attestation and not entry_attestations(entry):
        raise RegistryError(f"{entry['id']}@{entry['version']} has no attestation")

    installed = registry_recipes() / entry["id"]
    old = next((item for item in lock["recipes"] if item["id"] == entry["id"]), None)
    if (
        not force
        and old is not None
        and old.get("bundle") == entry["bundle"]
        and installed.is_dir()
    ):
        if file_hashes(installed) == entry["files"]:
            return entry
        raise RegistryError(
            f"{entry['id']} is installed but its files differ from the bundle; use --force"
        )
    if installed.exists() and not force:
        raise RegistryError(
            f"{entry['id']} is already installed; use `boxes registry update` or --force"
        )
    registry_recipes().parent.mkdir(parents=True, exist_ok=True)

    url = entry.get("bundle_url") or f"bundles/{entry['bundle']}.tar.gz"
    data = read_ref(reg["url"], url)
    if hashlib.sha256(data).hexdigest() != entry.get("tar_sha256"):
        raise RegistryError("download checksum mismatch")
    if len(data) != int(entry.get("size", len(data))):
        raise RegistryError("download size mismatch")

    temp_root = Path(tempfile.mkdtemp(dir=str(registry_recipes().parent)))
    tar_path = temp_root / "bundle.tar.gz"
    extract_to = temp_root / "recipe"
    try:
        tar_path.write_bytes(data)
        manifest = extract_bundle(tar_path, extract_to, expected_bundle=entry["bundle"])
        if (
            manifest.get("id") != entry["id"]
            or manifest.get("version") != entry["version"]
            or manifest.get("publisher") != entry["publisher"]
        ):
            raise RegistryError("bundle metadata does not match the index")
        if installed.exists():
            shutil.rmtree(installed)
        installed.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(extract_to), str(installed))
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)

    lock["recipes"] = [item for item in lock["recipes"] if item["id"] != entry["id"]]
    lock["recipes"].append({
        "id": entry["id"],
        "version": entry["version"],
        "registry": name,
        "bundle": entry["bundle"],
        "tar_sha256": entry["tar_sha256"],
        "size": entry.get("size"),
        "publisher": entry["publisher"],
        "publisher_key": entry["publisher_key"],
        "publisher_fingerprint": entry["publisher_fingerprint"],
        "bundle_signature": entry["bundle_signature"],
        "files": entry["files"],
        "attestations": entry_attestations(entry),
        "installed_at": _now(),
    })
    keys = _operator_keys(reg)
    matched = next(
        (key for key in keys if key["fingerprint"] == index.get("operator")),
        keys[0],
    )
    lock["registries"][name] = {
        "url": reg["url"],
        "operator_key": matched["key"],
        "operator_keys": keys,
        "operator_fingerprint": matched["fingerprint"],
        "sequence": int(index["sequence"]),
    }
    save_lock(lock)

    config = load_config()
    if name in config["registries"]:
        config["registries"][name]["sequence"] = int(index["sequence"])
        save_config(config)
    return entry


def update(
    registry_name: str | None = None,
    require_attestation: bool = False,
) -> list[dict]:
    lock = load_lock()
    changed = []
    for item in list(lock["recipes"]):
        if registry_name is not None and item["registry"] != registry_name:
            continue
        name = item["registry"]
        _name, reg = _get_registry(name)
        index = fetch_index(reg, floor=_sequence_floor(name, reg))
        _remember_sequence(name, index)
        entry = resolve(index, item["id"])
        if entry["bundle"] == item["bundle"]:
            continue
        install(
            item["id"], registry_name=name, force=True,
            require_attestation=require_attestation,
        )
        changed.append(entry)
    return changed


def uninstall(recipe_id: str) -> None:
    installed = registry_recipes() / recipe_id
    lock = load_lock()
    before = len(lock["recipes"])
    lock["recipes"] = [item for item in lock["recipes"] if item["id"] != recipe_id]
    if len(lock["recipes"]) == before and not installed.exists():
        raise RegistryError(f"{recipe_id} is not installed")
    if installed.exists():
        shutil.rmtree(installed)
    save_lock(lock)


def verify_installed(offline: bool = False) -> list[dict]:
    lock = load_lock()
    results = []
    for item in lock["recipes"]:
        installed = registry_recipes() / item["id"]
        errors: list[str] = []
        if not installed.is_dir():
            errors.append("installed directory is missing")
        else:
            actual = file_hashes(installed)
            expected = item.get("files", {})
            if actual != expected:
                missing = sorted(set(expected) - set(actual))
                extra = sorted(set(actual) - set(expected))
                changed = sorted(
                    name for name in set(actual) & set(expected)
                    if actual[name] != expected[name]
                )
                errors.append(
                    f"files differ (missing={missing}, extra={extra}, changed={changed})"
                )
        if bundle_hash(_entry_manifest(item)) != item["bundle"]:
            errors.append("lock manifest hash mismatch")
        try:
            _verify_entry(item)
        except RegistryError as e:
            errors.append(str(e))
        attestations = entry_attestations(item)
        for attestation in attestations:
            ok, error = attest.verify(attestation)
            if not ok:
                errors.append(f"attestation: {error}")
                continue
            if attestation.get("signer_fingerprint") != item.get("publisher_fingerprint"):
                errors.append("attestation signer is not the publisher")
            if attestation.get("recipe") != item["id"]:
                errors.append("attestation recipe mismatch")
            if attestation.get("version") != item["version"]:
                errors.append("attestation version mismatch")
            if attestation.get("files") != item.get("files"):
                errors.append("attestation files mismatch")
            if attestation.get("result") != "pass":
                errors.append("attestation is not a pass")

        if not offline:
            try:
                _name, reg = _get_registry(item["registry"])
                index = fetch_index(reg, floor=_sequence_floor(item["registry"], reg))
                _remember_sequence(item["registry"], index)
                entries = [
                    entry for entry in index["recipes"]
                    if entry.get("id") == item["id"]
                    and entry.get("version") == item["version"]
                    and entry.get("bundle") == item["bundle"]
                ]
                if _is_revoked(item, index):
                    errors.append("bundle is revoked")
                if not entries:
                    errors.append("recipe is no longer present in the registry index")
                else:
                    indexed = entries[0]
                    for field in (
                        "publisher", "publisher_key", "publisher_fingerprint",
                        "bundle_signature", "tar_sha256",
                    ):
                        if indexed.get(field) != item.get(field):
                            errors.append(f"registry index {field} differs from the lock")
                    if indexed.get("files") != item.get("files"):
                        errors.append("registry index file hashes differ from the lock")
                    if indexed.get("attestations") != item.get("attestations"):
                        errors.append("registry index attestations differ from the lock")
            except RegistryError as e:
                errors.append(str(e))
        results.append({
            "id": item["id"],
            "version": item["version"],
            "attested": bool(entry_attestations(item)),
            "errors": errors,
        })
    return results


# --- publish ----------------------------------------------------------------


def publish(
    recipe_dir: str | Path,
    registry_dir: str | Path,
    publisher: str,
    private_key: str | Path,
    operator_key: str | Path | None = None,
    attestation_path: str | Path | list[str | Path] | None = None,
) -> dict:
    recipe_dir = Path(recipe_dir)
    out = Path(registry_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "bundles").mkdir(exist_ok=True)

    recipe = load_recipe(recipe_dir / "recipe.yaml")
    errors = lint([recipe])
    if not recipe.verifiable:
        errors.append(f"{recipe.id}: registry recipes must have provision+poc")
    checked = check_recipe(recipe)
    errors.extend(checked.errors)
    if errors:
        raise RegistryError("recipe failed preflight: " + "; ".join(errors))

    operator_private = load_private(operator_key or private_key)
    operator_public = operator_private.public_key()
    publisher_private = load_private(private_key)
    publisher_public = publisher_private.public_key()

    index_path = out / "index.json"
    if index_path.is_file():
        existing = json.loads(index_path.read_text())
        signature = existing.pop("signature", None)
        if not signature or not verify_json(operator_public, existing, signature):
            raise RegistryError("existing index was not signed by this operator key")
        sequence = int(existing.get("sequence", 0)) + 1
        entries = list(existing.get("recipes", []))
        revoked_publishers = list(existing.get("revoked_publishers", []))
        revoked_bundles = list(existing.get("revoked_bundles", []))
    else:
        sequence = 1
        entries = []
        revoked_publishers = []
        revoked_bundles = []

    with tempfile.TemporaryDirectory(dir=str(out)) as tmp:
        tar_path = Path(tmp) / "bundle.tar.gz"
        manifest, digest, tar_sha = build_bundle(recipe_dir, publisher, tar_path)
        target = out / "bundles" / f"{digest}.tar.gz"
        target.write_bytes(tar_path.read_bytes())
    size = target.stat().st_size

    if attestation_path is None:
        attestation_paths = []
    elif isinstance(attestation_path, (str, Path)):
        attestation_paths = [attestation_path]
    else:
        attestation_paths = list(attestation_path)
    attestations: list[dict] = []
    for path in attestation_paths:
        try:
            value = json.loads(Path(path).read_text())
        except (OSError, json.JSONDecodeError) as e:
            raise RegistryError(f"cannot read attestation: {e}") from e
        ok, error = attest.verify(value)
        if not ok:
            raise RegistryError(f"attestation: {error}")
        if value.get("signer_fingerprint") != fingerprint(publisher_public):
            raise RegistryError("attestation must be signed by the publisher key")
        if value.get("recipe") != recipe.id or value.get("version") != recipe.version:
            raise RegistryError("attestation recipe/version does not match")
        if value.get("files") != manifest["files"]:
            raise RegistryError("attestation files do not match the bundle")
        if value.get("result") != "pass":
            raise RegistryError("attestation result is not pass")
        attestations.append(value)

    same = [
        entry for entry in entries
        if entry.get("id") == recipe.id and entry.get("version") == recipe.version
    ]
    if same:
        if any(entry.get("bundle") != digest for entry in same):
            raise RegistryError(
                f"{recipe.id}@{recipe.version} already exists with different content; "
                "bump the version"
            )
        if attestations:
            for entry in same:
                entry["attestations"] = attestations
                entry["attestation"] = attestations[0]
    else:
        entries.append({
            "id": recipe.id,
            "version": recipe.version,
            "publisher": publisher,
            "publisher_key": public_pem(publisher_public),
            "publisher_fingerprint": fingerprint(publisher_public),
            "bundle": digest,
            "bundle_signature": sign(publisher_private, digest.encode("ascii")),
            "files": manifest["files"],
            "attestations": attestations,
            "attestation": attestations[0] if attestations else None,
            "bundle_url": f"bundles/{digest}.tar.gz",
            "tar_sha256": tar_sha,
            "size": size,
            "metadata": {
                "description": recipe.description,
                "os": recipe.os,
                "difficulty": recipe.difficulty,
                "tools": recipe.tools or [],
                "poc_backend": recipe.poc_backend,
            },
        })
        sequence = sequence if index_path.is_file() else 1
    entries.sort(key=lambda entry: (entry["id"], _version_key(entry["version"])))

    body = {
        "schema": REGISTRY_SCHEMA,
        "sequence": sequence,
        "generated_at": _now(),
        "expires_at": _expiry(),
        "revoked_publishers": revoked_publishers,
        "revoked_bundles": revoked_bundles,
        "operator": fingerprint(operator_public),
        "recipes": entries,
    }
    body["signature"] = sign_json(operator_private, body)
    _write_json(index_path, body)
    return body


def publish_api(
    url: str,
    recipe_dir: str | Path,
    publisher: str,
    private_key: str | Path,
    attestation_path: str | Path | list[str | Path] | None = None,
) -> dict:
    import base64
    import urllib.error
    import urllib.request

    recipe_dir = Path(recipe_dir)
    recipe = load_recipe(recipe_dir / "recipe.yaml")
    errors = lint([recipe])
    if not recipe.verifiable:
        errors.append(f"{recipe.id}: registry recipes must have provision+poc")
    errors.extend(check_recipe(recipe).errors)
    if errors:
        raise RegistryError("recipe failed preflight: " + "; ".join(errors))

    if attestation_path is None:
        attestation_paths = []
    elif isinstance(attestation_path, (str, Path)):
        attestation_paths = [attestation_path]
    else:
        attestation_paths = list(attestation_path)
    attestations = []
    for path in attestation_paths:
        try:
            attestations.append(json.loads(Path(path).read_text()))
        except (OSError, json.JSONDecodeError) as e:
            raise RegistryError(f"cannot read attestation: {e}") from e

    with tempfile.TemporaryDirectory() as tmp:
        tar = Path(tmp) / "bundle.tar.gz"
        manifest, digest, _tar_sha = build_bundle(recipe_dir, publisher, tar)
        private = load_private(private_key)
        public = private.public_key()
        payload = {
            "id": recipe.id,
            "version": recipe.version,
            "publisher": publisher,
            "publisher_key": public_pem(public),
            "bundle": base64.b64encode(tar.read_bytes()).decode("ascii"),
            "signature": sign(private, digest.encode("ascii")),
            "attestations": attestations,
        }
    request = urllib.request.Request(
        url.rstrip("/") + "/v1/publish",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise RegistryError(f"publish failed ({e.code}): {detail}") from e
    except OSError as e:
        raise RegistryError(f"cannot reach registry: {e}") from e


# --- query ------------------------------------------------------------------


def revoke(
    registry_dir: str | Path,
    operator_key: str | Path,
    publisher: str | None = None,
    bundle: str | None = None,
) -> dict:
    if not publisher and not bundle:
        raise RegistryError("revoke needs a publisher fingerprint or bundle hash")
    index_path = Path(registry_dir) / "index.json"
    if not index_path.is_file():
        raise RegistryError(f"no registry index at {index_path}")
    index = json.loads(index_path.read_text())
    signature = index.pop("signature", None)
    operator_private = load_private(operator_key)
    if not signature or not verify_json(operator_private.public_key(), index, signature):
        raise RegistryError("index was not signed by this operator key")
    if publisher and publisher not in index.setdefault("revoked_publishers", []):
        index["revoked_publishers"].append(publisher)
    if bundle and bundle not in index.setdefault("revoked_bundles", []):
        index["revoked_bundles"].append(bundle)
    index["sequence"] = int(index.get("sequence", 0)) + 1
    index["generated_at"] = _now()
    index["expires_at"] = _expiry()
    index["operator"] = fingerprint(operator_private.public_key())
    index["signature"] = sign_json(operator_private, index)
    _write_json(index_path, index)
    return index


def rotate(
    registry_dir: str | Path,
    old_key: str | Path,
    new_key: str | Path,
) -> dict:
    index_path = Path(registry_dir) / "index.json"
    if not index_path.is_file():
        raise RegistryError(f"no registry index at {index_path}")
    index = json.loads(index_path.read_text())
    signature = index.pop("signature", None)
    old_private = load_private(old_key)
    if not signature or not verify_json(old_private.public_key(), index, signature):
        raise RegistryError("index was not signed by the old key")
    new_private = load_private(new_key)
    index["sequence"] = int(index.get("sequence", 0)) + 1
    index["generated_at"] = _now()
    index["expires_at"] = _expiry()
    index["operator"] = fingerprint(new_private.public_key())
    index["signature"] = sign_json(new_private, index)
    _write_json(index_path, index)
    return index


def search(query: str, registry_name: str | None = None) -> list[dict]:
    name, reg = _get_registry(registry_name)
    index = fetch_index(reg, floor=_sequence_floor(name, reg))
    _remember_sequence(name, index)
    needle = query.lower()
    latest: dict[str, dict] = {}
    for entry in index["recipes"]:
        metadata = entry.get("metadata", {})
        haystack = " ".join(
            str(part)
            for part in (
                entry.get("id"),
                entry.get("publisher"),
                metadata.get("description", ""),
            )
        ).lower()
        if needle not in haystack or _is_revoked(entry, index):
            continue
        current = latest.get(entry["id"])
        if current is None or _version_key(entry["version"]) > _version_key(current["version"]):
            latest[entry["id"]] = entry
    return [latest[key] for key in sorted(latest)]


def installed() -> list[dict]:
    lock = load_lock()
    return lock["recipes"]


def is_registry_recipe(recipe: Recipe) -> bool:
    if recipe.path is None:
        return False
    try:
        recipe.path.resolve().relative_to(registry_recipes().resolve())
        return True
    except ValueError:
        return False
