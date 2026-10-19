import pytest

from boxes.osinfo import DEFAULT_OS, PROFILES, SUPPORTED_OS, profile, vm_store


def test_profiles_are_complete():
    assert set(SUPPORTED_OS) == set(PROFILES)
    assert DEFAULT_OS in PROFILES
    for name, prof in PROFILES.items():
        assert prof.name == name
        assert prof.cloud_url and prof.cloud_sums and prof.cloud_image
        assert prof.cloud_sums_algo in {"sha256", "sha512"}


def test_profile_lookup_and_unsupported_os():
    assert profile("debian-12").codename == "bookworm"
    with pytest.raises(ValueError, match="unsupported OS"):
        profile("rocky-9")


def test_vm_store_is_per_os(monkeypatch, tmp_path):
    monkeypatch.setenv("BOXES_VM_STORE", str(tmp_path))
    assert vm_store("ubuntu-22.04") == tmp_path
    assert vm_store("debian-12") == tmp_path / "debian-12"
    assert vm_store("ubuntu-24.04") == tmp_path / "ubuntu-24.04"
