"""Base image management.

A base image is built once (network allowed) and every machine container is
created from it with ``--network none``. Recipes therefore never need network
access at verify time.
"""

from __future__ import annotations

from pathlib import Path

from .backends.base import Backend, ExecResult

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def image_tag(os_name: str) -> str:
    return f"boxes/base:{os_name}"


def image_context(os_name: str) -> Path:
    return PROJECT_ROOT / "images" / os_name


def ensure_image(backend: Backend, os_name: str, rebuild: bool = False) -> ExecResult:
    tag = image_tag(os_name)
    if not rebuild and backend.image_exists(tag):
        return ExecResult(0, f"image {tag} already present", "")
    context = image_context(os_name)
    if not (context / "Dockerfile").is_file():
        return ExecResult(1, "", f"no base image Dockerfile at {context}/Dockerfile")
    return backend.build_image(tag, str(context))
