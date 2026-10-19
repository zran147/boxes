"""Execution backends.

The fast path uses containers (Docker implemented today, Incus easy to add);
full-fidelity recipes will use QEMU later behind the same interface.
"""

from .base import Backend, ExecResult
from .fake import FakeBackend

__all__ = ["Backend", "ExecResult", "FakeBackend", "get_backend"]


def get_backend(name: str = "docker", **kwargs) -> Backend:
    if name == "docker":
        from .docker import DockerBackend

        return DockerBackend(**kwargs)
    if name == "qemu":
        from .qemu import QemuBackend

        return QemuBackend(**kwargs)
    if name == "fake":
        return FakeBackend()
    raise ValueError(f"unknown backend {name!r} (expected 'docker', 'qemu' or 'fake')")
