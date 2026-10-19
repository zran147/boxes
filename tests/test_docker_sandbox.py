from boxes.backends.base import ExecResult
from boxes.backends.docker import ATTACKER_CAPS, TARGET_CAPS, DockerBackend


def _capture(backend, monkeypatch):
    calls = []

    def fake(args, **kwargs):
        calls.append(args)
        return ExecResult(0, "", "")

    monkeypatch.setattr(backend, "_run", fake)
    return calls


def test_locked_sandbox_flags(monkeypatch):
    backend = DockerBackend(sandbox="locked")
    calls = _capture(backend, monkeypatch)
    assert backend.create("boxes-target-x", "img", "none").ok
    assert backend.create("boxes-attacker-x", "img", "none").ok
    target, attacker = calls

    assert "--cap-drop" in target and "ALL" in target
    for cap in TARGET_CAPS:
        assert cap in target
    assert "--security-opt" not in target  # setuid simulation must work
    assert "--ulimit" in target and "nofile=4096:4096" in target

    assert "--cap-drop" in attacker and "ALL" in attacker
    for cap in ATTACKER_CAPS:
        assert cap in attacker
    assert "--security-opt" in attacker
    assert "no-new-privileges" in attacker


def test_trusted_sandbox_has_no_hardening_flags():
    backend = DockerBackend(sandbox="trusted")
    assert backend.sandbox == "trusted"
