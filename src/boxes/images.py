"""Base image management.

A base image is built once (network allowed) and every machine container is
created from it with ``--network none``. Recipes therefore never need network
access at verify time.
"""

from __future__ import annotations

from pathlib import Path

from . import toolkit
from .backends.base import Backend, ExecResult

PROJECT_ROOT = Path(__file__).resolve().parents[2]


ATTACKER_TAG = "boxes/attacker:latest"


def image_tag(os_name: str) -> str:
    return f"boxes/base:{os_name}"


def attacker_image() -> str:
    return ATTACKER_TAG


def image_context(os_name: str) -> Path:
    return PROJECT_ROOT / "images" / os_name


def _ensure(backend: Backend, tag: str, context: Path, rebuild: bool) -> ExecResult:
    if not rebuild and backend.image_exists(tag):
        return ExecResult(0, f"image {tag} already present", "")
    if not (context / "Dockerfile").is_file():
        return ExecResult(1, "", f"no Dockerfile at {context}/Dockerfile")
    return backend.build_image(tag, str(context))


def ensure_image(backend: Backend, os_name: str, rebuild: bool = False) -> ExecResult:
    return _ensure(backend, image_tag(os_name), image_context(os_name), rebuild)


def ensure_attacker_image(backend: Backend, rebuild: bool = False) -> ExecResult:
    toolkit.write_context()
    return _ensure(backend, attacker_image(), image_context("attacker"), rebuild)
