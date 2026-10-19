from boxes.values import format_value


def test_format_value_bools_and_scalars():
    assert format_value(True) == "true"
    assert format_value(False) == "false"
    assert format_value(8080) == "8080"
    assert format_value("x") == "x"
