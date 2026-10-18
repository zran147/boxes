from pathlib import Path

from boxes.backends import FakeBackend
from boxes.cache import Cache, machine_key, recipe_key
from boxes.facts import parse_fact
from boxes.harness import Fixture
from boxes.recipe import Recipe
from boxes.runner import verify_recipes


def make_recipe(tmp_path: Path, rid: str, body: str = "echo hi\n", assets: bool = False) -> Recipe:
    d = tmp_path / rid
    d.mkdir()
    (d / "recipe.yaml").write_text(f"id: {rid}\n")
    (d / "provision.sh").write_text(body)
    (d / "poc.sh").write_text(body)
    if assets:
        (d / "files").mkdir()
        (d / "files" / "payload.txt").write_text("payload\n")
    return Recipe(
        id=rid,
        version="1.0.0",
        kind="privesc",
        os=["ubuntu-*"],
        difficulty=0.1,
        requires=[parse_fact("open_port($h, 80)")],
        provides=[parse_fact("access_root()")],
        yields=[],
        params={},
        walkthrough="",
        provision="provision.sh",
        poc="poc.sh",
        poc_backend="container",
        assets="files" if assets else None,
        path=d / "recipe.yaml",
    )


def fx(recipe: Recipe) -> Fixture:
    return Fixture(
        recipe_id=recipe.id, os="ubuntu-22.04", params={}, requires=[], provides=[],
        walkthrough="", context={"os": "ubuntu-22.04"},
    )


def test_assets_are_copied_and_exposed_via_env(tmp_path):
    rec = make_recipe(tmp_path, "with-assets", assets=True)
    backend = FakeBackend()

    result = verify_recipes([(rec, fx(rec))], backend, "img", jobs=1)[0]

    assert result.ok
    puts = [c for c in backend.calls if c[0] == "put"]
    assert len(puts) == 1
    assert puts[0][2].endswith("/files/.")
    exec_envs = [c[4] for c in backend.calls if c[0] == "exec" and c[4]]
    assert exec_envs
    assert all(e["BOX_ASSETS"] == "/opt/boxes/with-assets" for e in exec_envs)


def test_recipe_key_changes_when_recipe_content_changes(tmp_path):
    rec = make_recipe(tmp_path, "changing")
    before = recipe_key(rec, {"os": "ubuntu-22.04"}, "img-id", "container")
    (rec.dir / "poc.sh").write_text("something else\n")
    after = recipe_key(rec, {"os": "ubuntu-22.04"}, "img-id", "container")
    assert before != after


def test_cache_roundtrip_and_clear(tmp_path):
    cache = Cache(tmp_path / "cache.json")
    assert cache.get("k") is None
    cache.put("k", {"recipe": "x"})
    assert cache.get("k")["recipe"] == "x"
    cache.clear()
    assert cache.get("k") is None


def test_second_verification_is_served_from_cache(tmp_path):
    rec = make_recipe(tmp_path, "cached")
    cache = Cache(tmp_path / "cache.json")
    backend = FakeBackend()
    pairs = [(rec, fx(rec))]

    first = verify_recipes(pairs, backend, "img", image_id="img-id", jobs=1, cache=cache)
    assert first[0].ok and not first[0].cached
    creates = len([c for c in backend.calls if c[0] == "create"])

    second = verify_recipes(pairs, backend, "img", image_id="img-id", jobs=1, cache=cache)
    assert second[0].cached
    assert len([c for c in backend.calls if c[0] == "create"]) == creates


def test_parallel_verification_preserves_input_order(tmp_path):
    recipes = [make_recipe(tmp_path, f"r{i}") for i in range(4)]
    results = verify_recipes([(r, fx(r)) for r in recipes], FakeBackend(), "img", jobs=3)
    assert [r.label for r in results] == [r.id for r in recipes]
    assert all(r.ok for r in results)


def test_machine_key_depends_on_build_seed(tmp_path):
    from boxes.manifest import materialize
    from boxes.planner import generate
    from boxes.registry import load_registry, select

    recipes = Path(__file__).resolve().parents[1] / "recipes"
    pool = select(load_registry(recipes), "ubuntu-22.04")
    plan = generate(pool, "ubuntu-22.04", 3, 2, 0)
    m1 = materialize(plan, 1)
    m2 = materialize(plan, 2)
    k1 = machine_key(plan, m1, "img-id", "container")
    k2 = machine_key(plan, m2, "img-id", "container")
    assert k1 != k2


def test_recipe_cache_key_includes_the_apt_snapshot(tmp_path):
    rec = make_recipe(tmp_path, "snap")
    cache = Cache(tmp_path / "cache.json")
    backend = FakeBackend()
    pairs = [(rec, fx(rec))]

    first = verify_recipes(
        pairs, backend, "img", image_id="img-id", jobs=1, cache=cache,
        apt_snapshot="20240101T000000Z",
    )
    assert first[0].ok and not first[0].cached

    second = verify_recipes(
        pairs, backend, "img", image_id="img-id", jobs=1, cache=cache,
        apt_snapshot="20240201T000000Z",
    )
    assert second[0].ok and not second[0].cached
    assert len(cache) == 2
