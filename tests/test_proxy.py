from boxes import proxy as proxy_mod
from boxes.backends.base import ExecResult


def test_down_does_not_pass_a_pid_to_provision_down(monkeypatch):
    calls = []

    def fake_run(args, timeout=180):
        calls.append(args)
        if args[:2] == ["docker", "inspect"]:
            return ExecResult(0, "123\n", "")
        return ExecResult(0, "", "")

    monkeypatch.setattr(proxy_mod, "_run", fake_run)
    monkeypatch.setenv("BOXES_BIN", "/usr/local/bin/boxes")

    assert proxy_mod.down(clean=False).ok
    net_calls = [call for call in calls if "net" in call]
    assert net_calls == [["sudo", "-n", "/usr/local/bin/boxes", "net", "provision-down"]]


def test_clean_removes_network_volume_and_artifacts(monkeypatch, tmp_path):
    calls = []

    def fake_run(args, timeout=180):
        calls.append(args)
        if args[:2] == ["docker", "inspect"]:
            return ExecResult(0, "123\n", "")
        return ExecResult(0, "", "")

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    monkeypatch.setattr(proxy_mod, "_run", fake_run)
    monkeypatch.setattr(proxy_mod, "ARTIFACTS_DIR", artifacts)
    monkeypatch.setenv("BOXES_BIN", "/usr/local/bin/boxes")

    assert proxy_mod.down(clean=True).ok
    assert ["docker", "network", "rm", "boxes-provision"] in calls
    assert ["docker", "network", "rm", "boxes-egress"] in calls
    assert ["docker", "volume", "rm", "-f", "boxes-proxy-cache"] in calls
    assert not artifacts.exists()
