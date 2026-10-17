import getpass
import os

import pytest

from boxes.nethelper import NetError, _validate, down, up


def test_validate_accepts_normal_values():
    pid, user, vm_ip, atk_ip = _validate(
        "m1", os.getpid(), getpass.getuser(), "10.66.1.2", "10.66.1.3"
    )
    assert pid == os.getpid()
    assert vm_ip != atk_ip


def test_validate_rejects_bad_machine_id():
    with pytest.raises(NetError):
        _validate("Bad_Name", os.getpid(), getpass.getuser(), "10.66.1.2", "10.66.1.3")


def test_validate_rejects_out_of_subnet_ip():
    with pytest.raises(NetError):
        _validate("m1", os.getpid(), getpass.getuser(), "10.0.0.2", "10.66.1.3")


def test_validate_rejects_equal_ips():
    with pytest.raises(NetError):
        _validate("m1", os.getpid(), getpass.getuser(), "10.66.1.2", "10.66.1.2")


@pytest.mark.skipif(os.geteuid() == 0, reason="must be non-root")
def test_up_and_down_require_root():
    with pytest.raises(NetError):
        up("m1", os.getpid())
    with pytest.raises(NetError):
        down("m1")
