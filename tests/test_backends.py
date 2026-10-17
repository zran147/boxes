from pathlib import Path

from boxes.backends import get_backend
from boxes.backends.qemu import QemuBackend


def test_qemu_backend_reports_vm_fidelity():
    backend = get_backend("qemu")
    assert backend.fidelity == "vm"


def test_qemu_backend_is_unavailable_without_a_base(tmp_path):
    backend = QemuBackend(
        store=tmp_path,
        base=tmp_path / "missing.qcow2",
        key=tmp_path / "missing_key",
    )
    assert not backend.available()


def test_qemu_backend_is_unavailable_without_a_key(tmp_path):
    base = tmp_path / "base.qcow2"
    base.write_bytes(b"not really a qcow2")
    backend = QemuBackend(store=tmp_path, base=base, key=tmp_path / "missing_key")
    assert not backend.available()
