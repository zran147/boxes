"""QEMU acceleration selection.

``auto`` (the default) uses KVM when ``/dev/kvm`` is usable and the QEMU binary
reports the ``kvm`` accelerator, and falls back to TCG otherwise. Both the VM
base prebake and runtime verification use this module, so a KVM-capable host
does not silently run either step under TCG.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

QEMU = "qemu-system-x86_64"
ENV = "BOXES_QEMU_ACCEL"
VALID = ("auto", "kvm", "tcg")


def kvm_available(qemu: str = QEMU) -> bool:
    dev = Path("/dev/kvm")
    if not dev.exists() or not os.access(dev, os.R_OK | os.W_OK):
        return False
    try:
        proc = subprocess.run(
            [qemu, "-accel", "help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "kvm" in (proc.stdout + proc.stderr).lower()


def requested(value: str | None = None) -> str:
    choice = (value or os.environ.get(ENV) or "auto").strip().lower()
    if choice not in VALID:
        raise ValueError(
            f"QEMU accel must be one of {', '.join(VALID)}; got {choice!r}"
        )
    return choice


def resolve(value: str | None = None, *, available: bool | None = None) -> str:
    """Return ``kvm`` or ``tcg`` for an ``auto|kvm|tcg`` request."""
    choice = requested(value)
    if choice == "tcg":
        return "tcg"
    usable = kvm_available() if available is None else available
    if choice == "kvm":
        if not usable:
            raise ValueError(
                "KVM acceleration was requested but /dev/kvm is not usable "
                "(missing, not readable/writable, or QEMU has no kvm accelerator)"
            )
        return "kvm"
    return "kvm" if usable else "tcg"


def args(accel: str) -> list[str]:
    if accel == "kvm":
        return ["-accel", "kvm", "-cpu", "host"]
    if accel == "tcg":
        return ["-accel", "tcg,thread=multi", "-cpu", "max"]
    raise ValueError(f"unknown QEMU accel {accel!r}")
