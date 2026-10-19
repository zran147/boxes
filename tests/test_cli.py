from boxes.cli import main


def test_multi_path_needs_at_least_two(capsys):
    assert main(["gen", "--multi-path", "1", "--to-user", "1", "--to-root", "1"]) == 2
    assert "at least 2" in capsys.readouterr().err


def test_multi_path_generates_multiple_paths(capsys):
    assert main([
        "gen", "--multi-path", "2", "--seed", "0", "--build-seed", "1",
        "--to-user", "3", "--to-root", "2",
    ]) == 0
    out = capsys.readouterr().out
    assert "## Path 1" in out
    assert "## Path 2" in out


def test_multi_path_requires_machine_on_verify(capsys):
    assert main(["verify", "--multi-path", "2", "--recipe", "x"]) == 2
    assert "only applies to --machine" in capsys.readouterr().err


def test_qemu_rejects_an_unsupported_os(capsys):
    rc = main(["verify", "--backend", "qemu", "--os", "rocky-9", "--recipe", "vm-kernel-probe"])
    assert rc == 2
    assert "unsupported VM OS" in capsys.readouterr().err


def test_qemu_image_rejects_an_unsupported_os(capsys):
    rc = main(["image", "build", "--backend", "qemu", "--os", "rocky-9"])
    assert rc == 2
    assert "unsupported VM OS" in capsys.readouterr().err


def test_gen_difficulty_filter(capsys):
    assert main([
        "gen", "--difficulty", "hard", "--to-user", "1", "--to-root", "1", "--seed", "0",
    ]) == 0
    out = capsys.readouterr().out
    assert "difficulty: **8/10 (hard)**" in out
    assert "user 8/10 (hard)" in out


def test_difficulty_requires_machine_on_verify(capsys):
    assert main(["verify", "--difficulty", "easy", "--recipe", "x"]) == 2
    assert "only apply to --machine" in capsys.readouterr().err


def test_image_tools_lists_the_attacker_toolkit(capsys):
    assert main(["image", "tools"]) == 0
    out = capsys.readouterr().out
    assert "nmap" in out
    assert "impacket-wmiexec" in out


def test_registry_keygen_cli(tmp_path, capsys):
    assert main(["registry", "keygen", "--out", str(tmp_path / "dev")]) == 0
    out = capsys.readouterr().out
    assert "fingerprint:" in out
    assert (tmp_path / "dev.key").is_file()
    assert (tmp_path / "dev.pub").is_file()


def test_registry_list_empty_cli(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("BOXES_CONFIG_FILE", str(tmp_path / "config.json"))
    monkeypatch.setenv("BOXES_LOCKFILE", str(tmp_path / "boxes.lock"))
    monkeypatch.setenv("BOXES_REGISTRY_DIR", str(tmp_path / "installed"))
    assert main(["registry", "list"]) == 0
    capsys.readouterr()
