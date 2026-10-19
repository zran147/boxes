import pytest

from boxes.harness import check_recipe
from boxes.lint import lint
from boxes.registry import load_registry
from boxes.scaffold import create_recipe


@pytest.mark.parametrize("kind", ["discovery", "service-access", "creds", "foothold", "privesc"])
def test_scaffold_passes_lint_and_harness(tmp_path, kind):
    create_recipe(tmp_path, f"demo-{kind}", kind)
    recipes = load_registry(tmp_path)
    assert len(recipes) == 1
    assert lint(recipes) == []
    assert check_recipe(recipes[0]).ok


def test_scaffold_refuses_duplicate(tmp_path):
    create_recipe(tmp_path, "dupe", "creds")
    with pytest.raises(FileExistsError):
        create_recipe(tmp_path, "dupe", "creds")


def test_scaffold_rejects_bad_id(tmp_path):
    with pytest.raises(ValueError):
        create_recipe(tmp_path, "Bad_ID", "creds")


def test_scaffold_rejects_bad_kind(tmp_path):
    with pytest.raises(ValueError):
        create_recipe(tmp_path, "x", "nope")


def test_scaffold_uses_custom_os_and_difficulty(tmp_path):
    path = create_recipe(tmp_path, "custom", "privesc", os_patterns=["debian-*"], difficulty="hard")
    text = path.read_text()
    assert "debian-*" in text
    assert "difficulty: 8" in text
