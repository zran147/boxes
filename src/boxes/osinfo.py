"""Supported operating-system profiles.

Docker uses one base image per OS. QEMU uses the matching cloud image and a
per-OS store (the Ubuntu 22.04 store stays at `.boxes-vm` for compatibility).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OS = "ubuntu-22.04"


@dataclass(frozen=True)
class OSProfile:
    name: str
    codename: str
    cloud_url: str
    cloud_sums: str
    cloud_sums_algo: str
    cloud_image: str


PROFILES: dict[str, OSProfile] = {
    "ubuntu-22.04": OSProfile(
        name="ubuntu-22.04",
        codename="jammy",
        cloud_url="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img",
        cloud_sums="https://cloud-images.ubuntu.com/jammy/current/SHA256SUMS",
        cloud_sums_algo="sha256",
        cloud_image="jammy-server-cloudimg-amd64.img",
    ),
    "ubuntu-24.04": OSProfile(
        name="ubuntu-24.04",
        codename="noble",
        cloud_url="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
        cloud_sums="https://cloud-images.ubuntu.com/noble/current/SHA256SUMS",
        cloud_sums_algo="sha256",
        cloud_image="noble-server-cloudimg-amd64.img",
    ),
    "debian-12": OSProfile(
        name="debian-12",
        codename="bookworm",
        cloud_url=(
            "https://cloud.debian.org/images/cloud/bookworm/latest/"
            "debian-12-genericcloud-amd64.qcow2"
        ),
        cloud_sums="https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS",
        cloud_sums_algo="sha512",
        cloud_image="debian-12-genericcloud-amd64.qcow2",
    ),
}

SUPPORTED_OS = tuple(PROFILES)


def profile(os_name: str) -> OSProfile:
    try:
        return PROFILES[os_name]
    except KeyError as e:
        raise ValueError(
            f"unsupported OS {os_name!r}; supported: {', '.join(SUPPORTED_OS)}"
        ) from e


def vm_store(os_name: str, root: str | Path | None = None) -> Path:
    base = Path(root) if root else Path(
        os.environ.get("BOXES_VM_STORE", PROJECT_ROOT / ".boxes-vm")
    )
    return base if os_name == DEFAULT_OS else base / os_name
