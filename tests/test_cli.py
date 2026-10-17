from boxes.cli import main


def test_multi_path_is_gated_for_gen(capsys):
    assert main(["gen", "--multi-path", "--to-user", "1", "--to-root", "1"]) == 2
    err = capsys.readouterr().err
    assert "multi-path" in err
    assert "not implemented" in err


def test_multi_path_is_gated_for_verify_before_touching_docker(capsys):
    assert main(["verify", "--machine", "--multi-path", "--to-user", "1", "--to-root", "1"]) == 2
    err = capsys.readouterr().err
    assert "multi-path" in err
