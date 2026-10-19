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


def test_qemu_image_id_does_not_collide_across_os_stores(tmp_path):
    ids = []
    for name in ("ubuntu-22.04", "debian-12"):
        base = tmp_path / name / "base-prebaked.qcow2"
        base.parent.mkdir(parents=True)
        base.write_bytes(b"same-size")
        backend = QemuBackend(store=base.parent, base=base, key=tmp_path / "missing")
        ids.append(backend.image_id("ignored"))
    assert ids[0] != ids[1]


def test_qemu_backend_uses_a_per_os_store(monkeypatch, tmp_path):
    monkeypatch.setenv("BOXES_VM_STORE", str(tmp_path))
    backend = QemuBackend(os_name="debian-12")
    assert backend.store == tmp_path / "debian-12"
    assert backend.base == backend.store / "base-prebaked.qcow2"

    default = QemuBackend(os_name="ubuntu-22.04")
    assert default.store == tmp_path


def test_isolated_qemu_refuses_networking(tmp_path):
    base = tmp_path / "base.qcow2"
    base.write_bytes(b"x")
    key = tmp_path / "key"
    key.write_text("x")
    backend = QemuBackend(store=tmp_path, base=base, key=key, sandbox="isolated")
    assert not backend.network_create("x", 1).ok
    assert not backend.attach_attacker("x", 1).ok
    assert not backend.create("x", "img", network="net").ok
    assert not backend.create("x", "img", provision=True).ok
