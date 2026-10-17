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
