import pytest

from boxes import accel


def test_auto_uses_kvm_when_available():
    assert accel.resolve("auto", available=True) == "kvm"
    assert accel.resolve("auto", available=False) == "tcg"


def test_tcg_forces_tcg():
    assert accel.resolve("tcg", available=True) == "tcg"


def test_kvm_requires_kvm():
    assert accel.resolve("kvm", available=True) == "kvm"
    with pytest.raises(ValueError):
        accel.resolve("kvm", available=False)


def test_env_sets_the_default(monkeypatch):
    monkeypatch.setenv("BOXES_QEMU_ACCEL", "tcg")
    assert accel.resolve(None, available=True) == "tcg"
    assert accel.resolve("auto", available=True) == "kvm"


def test_invalid_accel_is_rejected():
    with pytest.raises(ValueError):
        accel.resolve("bogus", available=True)


def test_accel_args():
    assert accel.args("kvm") == ["-accel", "kvm", "-cpu", "host"]
    assert accel.args("tcg") == ["-accel", "tcg,thread=multi", "-cpu", "max"]
    with pytest.raises(ValueError):
        accel.args("bogus")
