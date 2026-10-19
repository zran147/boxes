from boxes import toolkit


def test_context_lists_are_generated_from_the_manifest():
    assert (toolkit.CONTEXT / "tools.txt").read_text().splitlines() == toolkit.apt_packages()
    pip_text = (toolkit.CONTEXT / "pip.txt").read_text().splitlines()
    assert pip_text == toolkit.pip_packages()


def test_toolkit_has_the_expected_core_commands():
    assert {
        "curl", "ssh", "sshpass", "nmap", "gobuster", "hydra",
        "impacket-secretsdump", "impacket-wmiexec",
    } <= toolkit.commands()


def test_shipped_recipe_tools_are_all_in_the_manifest():
    from pathlib import Path
    from boxes.registry import load_registry

    recipes = load_registry(Path(__file__).resolve().parents[1] / "recipes")
    known = toolkit.commands()
    for recipe in recipes:
        assert set(recipe.tools or []) <= known, recipe.id
