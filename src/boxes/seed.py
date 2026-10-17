"""Deterministic sub-seeding."""

from __future__ import annotations

import hashlib


def derive_seed(base: int, *parts: str) -> int:
    """Deterministic sub-seed, independent of call order."""
    material = ":".join([str(base), *parts]).encode()
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")
