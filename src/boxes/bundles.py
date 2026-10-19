"""Content-addressed recipe bundles.

A bundle is a deterministic tar.gz containing bundle.json plus the recipe
files. bundle.json lists each file's SHA-256; its canonical hash is the bundle
identity signed by the publisher.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path

from .recipe import load_recipe
from .signing import canonical_json

SCHEMA = 1
MANIFEST_NAME = "bundle.json"
_IGNORED_PARTS = {"__pycache__", ".git", ".boxes-cache"}
_IGNORED_SUFFIXES = {".pyc", ".pyo"}


def _relative_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in _IGNORED_PARTS for part in rel.parts):
            continue
        if path.suffix in _IGNORED_SUFFIXES or path.name == MANIFEST_NAME:
            continue
        files.append(path)
    return files


def file_hashes(root: Path) -> dict[str, str]:
    root = Path(root)
    out: dict[str, str] = {}
    for path in _relative_files(root):
        rel = path.relative_to(root).as_posix()
        out[rel] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def manifest_for(recipe_dir: Path, publisher: str) -> dict:
    recipe_dir = Path(recipe_dir)
    recipe = load_recipe(recipe_dir / "recipe.yaml")
    return {
        "schema": SCHEMA,
        "id": recipe.id,
        "version": recipe.version,
        "publisher": publisher,
        "files": file_hashes(recipe_dir),
    }


def bundle_hash(manifest: dict) -> str:
    return hashlib.sha256(canonical_json(manifest)).hexdigest()


def _tar_bytes(recipe_dir: Path, manifest: dict) -> bytes:
    data_files: dict[str, bytes] = {
        MANIFEST_NAME: canonical_json(manifest),
    }
    for path in _relative_files(recipe_dir):
        rel = path.relative_to(recipe_dir).as_posix()
        data_files[rel] = path.read_bytes()

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for name in sorted(data_files):
            data = data_files[name]
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    packed = io.BytesIO()
    with gzip.GzipFile(fileobj=packed, mode="wb", mtime=0, filename="") as gz:
        gz.write(raw.getvalue())
    return packed.getvalue()


def build_bundle(recipe_dir: Path, publisher: str, out_path: Path) -> tuple[dict, str, str]:
    recipe_dir = Path(recipe_dir)
    manifest = manifest_for(recipe_dir, publisher)
    digest = bundle_hash(manifest)
    data = _tar_bytes(recipe_dir, manifest)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(data)
    return manifest, digest, hashlib.sha256(data).hexdigest()


def read_bundle(path: Path) -> tuple[dict, dict[str, bytes]]:
    path = Path(path)
    with tarfile.open(path, "r:gz") as tar:
        members = {}
        for member in tar.getmembers():
            if not member.isfile():
                raise ValueError(f"bundle contains a non-regular file: {member.name}")
            name = member.name
            if name.startswith("/") or ".." in Path(name).parts:
                raise ValueError(f"unsafe bundle path: {name}")
            members[name] = tar.extractfile(member).read()
    if MANIFEST_NAME not in members:
        raise ValueError("bundle is missing bundle.json")
    manifest = json.loads(members[MANIFEST_NAME])
    files = {name: data for name, data in members.items() if name != MANIFEST_NAME}
    expected = manifest.get("files")
    if not isinstance(expected, dict):
        raise ValueError("bundle.json has no files map")
    if set(files) != set(expected):
        raise ValueError("bundle files do not match bundle.json")
    for name, digest in expected.items():
        actual = "sha256:" + hashlib.sha256(files[name]).hexdigest()
        if actual != digest:
            raise ValueError(f"bundle file hash mismatch: {name}")
    return manifest, files


def extract_bundle(path: Path, destination: Path, expected_bundle: str | None = None) -> dict:
    manifest, files = read_bundle(path)
    digest = bundle_hash(manifest)
    if expected_bundle is not None and digest != expected_bundle:
        raise ValueError(f"bundle hash mismatch: got {digest}, expected {expected_bundle}")
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError(destination)
    destination.mkdir(parents=True)
    (destination / MANIFEST_NAME).write_bytes(canonical_json(manifest))
    for name, data in files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return manifest
