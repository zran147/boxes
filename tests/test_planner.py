import random
import re
from pathlib import Path

import pytest

from boxes.facts import Var, parse_fact
from boxes.manifest import materialize
from boxes.planner import generate, generate_paths, is_relevant, satisfies
from boxes.registry import load_registry, select
from boxes.writeup import plan_to_dict, render_markdown

RECIPES = Path(__file__).resolve().parents[1] / "recipes"
OS = "ubuntu-22.04"


@pytest.fixture(scope="module")
def pool():
    return select(load_registry(RECIPES), OS)


@pytest.mark.parametrize("to_user,to_root", [(1, 1), (1, 2), (2, 1), (3, 1), (2, 2), (3, 2)])
@pytest.mark.parametrize("seed", [0, 1, 7, 42, 1337, 99999])
def test_generated_machines_are_valid(pool, to_user, to_root, seed):
    plan = generate(pool, OS, to_user, to_root, seed)
    assert plan is not None, f"no machine for {to_user}/{to_root} seed {seed}"

    # exact step counts
    assert plan.user_index == to_user - 1
    assert plan.root_index == to_user + to_root - 1

    # flag steps carry the right tag
    assert "user" in plan.steps[plan.user_index].recipe.yields
    assert "root" in plan.steps[plan.root_index].recipe.yields

    # every precondition was actually met, in order
    assert satisfies(plan)

    # and it is a causal chain (no filler steps)
    assert is_relevant(plan)


def test_infeasible_depth_returns_none(pool):
    # with the shipped recipe graph there is no 4-step chain to the root flag
    assert generate(pool, OS, 1, 4, 1) is None


def test_deterministic_under_same_seed(pool):
    a = generate(pool, OS, 3, 2, 123)
    b = generate(pool, OS, 3, 2, 123)
    assert [s.recipe.id for s in a.steps] == [s.recipe.id for s in b.steps]
    ma = materialize(a, 123)
    mb = materialize(b, 123)
    assert ma.values == mb.values


def test_writeup_has_no_unresolved_placeholders(pool):
    for seed in range(20):
        plan = generate(pool, OS, 3, 2, seed)
        m = materialize(plan, seed)
        text = render_markdown(plan, m) + str(plan_to_dict(plan, m))
        assert not re.findall(r"\{[A-Za-z0-9_.]+\}", text), f"seed {seed}"


def test_leaked_credentials_are_the_ones_used(pool):
    """The FTP recipe leaks creds; the SSH foothold must use exactly those."""
    plan = None
    foothold = None
    for seed in range(500):
        p = generate(pool, OS, 3, 2, seed)
        if not p or not any(s.recipe.id == "ftp-config-leak-creds" for s in p.steps):
            continue
        candidate = next(
            (s for s in p.steps if s.recipe.id == "ssh-creds-foothold"), None
        )
        if candidate is None:
            continue
        # The planner may combine a username and password from different
        # sources now that they are separate facts. Keep this regression test
        # focused on the case where SSH consumes the FTP pair together.
        if all(
            candidate.subst.get(f"ssh-creds-foothold#{p.steps.index(candidate)}.{name}")
            == Var(f"ftp-config-leak-creds#{p.steps.index(next(s for s in p.steps if s.recipe.id == 'ftp-config-leak-creds'))}.{source}")
            for name, source in (("u", "ssh_user"), ("p", "ssh_pass"))
        ):
            plan = p
            foothold = candidate
            break
    assert plan is not None, "no coupled FTP/SSH chain found"

    m = materialize(plan, 0)
    leak = next(s for s in plan.steps if s.recipe.id == "ftp-config-leak-creds")
    leak_ctx = m.step_context(leak)
    foot_ctx = m.step_context(foothold)
    assert leak_ctx["ssh_user"] == foot_ctx["u"]
    assert leak_ctx["ssh_pass"] == foot_ctx["p"]


def test_satisfies_backtracks_over_credential_choices():
    """satisfies() must not be fooled by the first fact that happens to match."""
    from boxes.facts import Var, parse_fact
    from boxes.planner import Plan, Step, _applications, initial_state
    from boxes.recipe import Recipe

    def mk(rid, kind, requires, provides, yields=()):
        return Recipe(
            id=rid, version="1.0.0", kind=kind, os=["ubuntu-*"], difficulty=2,
            requires=[parse_fact(x) for x in requires],
            provides=[parse_fact(x) for x in provides],
            yields=list(yields), params={}, walkthrough="",
        )

    producer = mk(
        "a", "creds", ["open_port($h, 80)"],
        ["creds(alice, pw1)", "creds(bob, pw2)", "creds.uname(bob)"],
    )
    consumer = mk(
        "b", "privesc", ["creds($u, $p)", "creds.uname($u)"],
        ["access_root()"], ["root"],
    )

    state = initial_state("ubuntu-22.04")
    a = list(_applications(producer, state, random.Random(0), "a#0"))[0]
    step_a = Step(producer, "a#0", a[2], a[0], a[1], a[3])
    b = list(_applications(consumer, step_a.state, random.Random(0), "b#1"))[0]
    step_b = Step(consumer, "b#1", b[2], b[0], b[1], b[3])

    # Alice matches the pair first but has no username fact; only Bob is consistent.
    assert satisfies(Plan("ubuntu-22.04", [step_a, step_b], 0))


def test_is_relevant_allows_fan_out_and_merge():
    """Two parallel branches from one step, merged at the goal, are valid."""
    from boxes.planner import Plan, Step
    from boxes.recipe import Recipe

    def step(rid, requires, provides, yields=()):
        r = Recipe(
            id=rid, version="1.0.0", kind="privesc", os=["ubuntu-*"], difficulty=2,
            requires=[parse_fact(x) for x in requires],
            provides=[parse_fact(x) for x in provides],
            yields=list(yields), params={}, walkthrough="",
        )
        return Step(r, f"{rid}#0", {}, r.requires, r.provides, [])

    plan = Plan(
        "ubuntu-22.04",
        [
            step("a", ["open_port($h, 80)"], ["knows(a, 1)", "knows(b, 2)"]),
            step("b", ["knows(a, 1)"], ["access_shell(alice)"]),
            step("c", ["knows(b, 2)"], ["creds(alice, pw)"]),
            step("d", ["access_shell(alice)", "creds(alice, pw)"], ["access_root()"], ["root"]),
        ],
        0,
    )
    # steps b and c do not share anything, so the old adjacent-only rule failed
    assert is_relevant(plan)


def test_is_relevant_rejects_dead_end_branch():
    from boxes.planner import Plan, Step
    from boxes.recipe import Recipe

    def step(rid, requires, provides, yields=()):
        r = Recipe(
            id=rid, version="1.0.0", kind="privesc", os=["ubuntu-*"], difficulty=2,
            requires=[parse_fact(x) for x in requires],
            provides=[parse_fact(x) for x in provides],
            yields=list(yields), params={}, walkthrough="",
        )
        return Step(r, f"{rid}#0", {}, r.requires, r.provides, [])

    plan = Plan(
        "ubuntu-22.04",
        [
            step("a", ["open_port($h, 80)"], ["knows(a, 1)", "knows(b, 2)"]),
            step("dead", ["knows(a, 1)"], ["knows(c, 3)"]),
            step("goal", ["knows(b, 2)"], ["access_root()"], ["root"]),
        ],
        0,
    )
    assert not is_relevant(plan)


def test_single_step_rce_is_reachable_at_depth_one(pool):
    plan = generate(pool, OS, 1, 1, 3)
    assert plan is not None
    assert plan.steps[0].recipe.kind == "foothold"
    assert "user" in plan.steps[0].recipe.yields


def test_generate_paths_returns_distinct_paths(pool):
    paths = generate_paths(pool, OS, 3, 2, 0, 2)
    assert len(paths) == 2
    chains = {tuple(s.recipe.id for s in p.steps) for p in paths}
    assert len(chains) == 2
    for path in paths:
        assert satisfies(path)
        assert is_relevant(path)


def test_generate_paths_dedupes_and_bounds(pool):
    paths = generate_paths(pool, OS, 1, 1, 0, 50)
    assert 1 <= len(paths) <= 50
    chains = [tuple(s.recipe.id for s in p.steps) for p in paths]
    assert len(chains) == len(set(chains))


def test_multi_path_writeup_and_json(pool):
    from boxes.writeup import paths_to_dict, render_machine_markdown

    paths = generate_paths(pool, OS, 3, 2, 0, 2)
    manifests = [materialize(p, 1) for p in paths]
    text = render_machine_markdown(paths, manifests)
    assert "## Path 1" in text and "## Path 2" in text
    data = paths_to_dict(paths, manifests)
    assert len(data["paths"]) == 2
    assert data["build_seed"] == manifests[0].build_seed


def test_unused_discovery_is_not_a_planner_candidate(pool):
    for seed in range(20):
        plan = generate(pool, OS, 3, 2, seed)
        assert plan is not None
        assert all(s.recipe.id != "vm-kernel-probe" for s in plan.steps)


def test_difficulty_is_the_hardest_recipe(pool):
    from boxes.difficulty import report

    easy = generate(pool, OS, 2, 1, 0, machine_difficulty="easy")
    assert easy is not None
    assert report(easy)["band"] == "easy"

    medium = generate(pool, OS, 2, 1, 0, machine_difficulty="medium")
    assert medium is not None
    assert report(medium)["band"] == "medium"

    hard = generate(pool, OS, 1, 1, 0, machine_difficulty="hard")
    assert hard is not None
    hard_summary = report(hard)
    assert hard_summary["band"] == "hard"
    assert hard_summary["user_band"] == "hard"


def test_user_and_root_difficulty_are_separate(pool):
    from boxes.difficulty import report

    user_hard = generate(pool, OS, 1, 1, 0, user_difficulty="hard")
    assert user_hard is not None
    assert report(user_hard)["user_band"] == "hard"

    root_hard = generate(pool, OS, 2, 2, 0, user_difficulty="easy", root_difficulty="hard")
    assert root_hard is not None
    assert report(root_hard)["user_band"] == "easy"
    assert report(root_hard)["root_band"] == "hard"
    assert report(root_hard)["band"] == "hard"


def test_literal_requirement_can_consume_a_variable_fact():
    from boxes.facts import parse_fact
    from boxes.planner import Plan, Step, _applications, initial_state
    from boxes.recipe import Recipe

    def mk(rid, kind, requires, provides, yields=()):
        return Recipe(
            id=rid, version="1.0.0", kind=kind, os=["ubuntu-*"], difficulty=2,
            requires=[parse_fact(x) for x in requires],
            provides=[parse_fact(x) for x in provides],
            yields=list(yields), params={}, walkthrough="",
        )

    producer = mk(
        "a", "discovery", ["open_port($h, 80)"],
        ["knows(path, $path)"],
    )
    consumer = mk(
        "b", "privesc", ["knows(path, admin)"],
        ["access_root()"], ["root"],
    )
    a = list(_applications(producer, initial_state("ubuntu-22.04"), random.Random(0), "a#0"))[0]
    step_a = Step(producer, "a#0", a[2], a[0], a[1], a[3])
    b = list(_applications(consumer, step_a.state, random.Random(0), "b#1"))[0]
    step_b = Step(consumer, "b#1", b[2], b[0], b[1], b[3])
    plan = Plan("ubuntu-22.04", [step_a, step_b], 0)
    assert satisfies(plan)
    assert is_relevant(plan)
