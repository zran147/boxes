"""The planner.

A machine is a *plan*: an ordered chain of recipe applications where every
recipe's ``requires`` are satisfied by facts produced earlier. The plan has two
phases:

* **user phase** -- exactly ``to_user`` steps, the last of which is tagged
  ``yields: [user]`` (that step is what gets you the user flag).
* **root phase** -- exactly ``to_root`` further steps, the last tagged
  ``yields: [root]``.

``open_port`` preconditions are *free*: since nmap is a prelude and not a step,
a recipe requiring a port implicitly asserts that the machine exposes it. The
union of required ports becomes the machine's service inventory (the thing the
builder will install, and the thing we cap for coherence).
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from . import difficulty as difficulty_mod
from .facts import Fact, rename_fact, subst_fact, unify_fact
from .recipe import Recipe
from .seed import derive_seed

TARGET = "target"
MAX_ATTEMPTS = 2000
MAX_BINDINGS = 64

PRELUDE = {"open_port", "os", "host"}


@dataclass
class Step:
    recipe: Recipe
    instance: str  # e.g. "ftp-config-leak-creds#2" (numbered per plan position)
    subst: dict
    requires: list[Fact]  # renamed, ungrounded
    provides: list[Fact]  # renamed, substituted (still may hold Vars)
    state: list[Fact] = field(default_factory=list)  # state *after* this step


@dataclass
class Plan:
    os_name: str
    steps: list[Step]
    seed: int

    @property
    def user_index(self) -> int:
        for i, s in enumerate(self.steps):
            if "user" in s.recipe.yields:
                return i
        raise RuntimeError("no user-flag step in plan")

    @property
    def root_index(self) -> int:
        for i, s in enumerate(self.steps):
            if "root" in s.recipe.yields:
                return i
        raise RuntimeError("no root-flag step in plan")

    @property
    def ports(self) -> list[int]:
        out: set[int] = set()
        for s in self.steps:
            for f in [*s.requires, *s.provides]:
                if f.pred == "open_port" and len(f.args) == 2 and isinstance(f.args[1], int):
                    out.add(f.args[1])
        return sorted(out)


def initial_state(os_name: str) -> list[Fact]:
    return [Fact("os", (os_name,)), Fact("host", (TARGET,))]


def common_prefix(paths: list[Plan], manifests: list | None = None) -> int:
    """Number of leading steps shared by every path.

    Instances alone are not enough: independent fallback paths can reuse the
    same recipe at the same position while binding its variables differently.
    When manifests are supplied, their grounded prefix contexts must match too;
    a branch can constrain a prefix variable and change what was provisioned.
    """
    def identity(step: Step, manifest) -> tuple:
        binding = tuple(
            sorted((name, repr(value)) for name, value in step.subst.items())
        )
        if manifest is None:
            return (step.instance, binding)
        context = tuple(
            sorted((name, repr(value)) for name, value in manifest.step_context(step).items())
        )
        return (step.instance, binding, context)

    length = 0
    while all(len(path.steps) > length for path in paths):
        values = {
            identity(path.steps[length], manifests[index] if manifests else None)
            for index, path in enumerate(paths)
        }
        if len(values) != 1:
            break
        length += 1
    return length


def _candidate_facts(pat: Fact, state: list[Fact]) -> list[Fact]:
    """Facts in ``state`` that could satisfy ``pat`` (incl. assumed ports)."""
    out = [f for f in state if unify_fact(pat, f, {}) is not None]
    if pat.pred == "open_port" and len(pat.args) == 2:
        assumed = Fact("open_port", (TARGET, pat.args[1]))
        if assumed not in state and unify_fact(pat, assumed, {}) is not None:
            out.append(assumed)
    return out


def _bind_requires(reqs: list[Fact], state: list[Fact], rng: random.Random) -> list[dict]:
    results: list[dict] = []

    def rec(i: int, s: dict) -> None:
        if len(results) >= MAX_BINDINGS:
            return
        if i == len(reqs):
            results.append(dict(s))
            return
        for f in _candidate_facts(reqs[i], state):
            ns = unify_fact(reqs[i], f, s)
            if ns is not None:
                rec(i + 1, ns)
                if len(results) >= MAX_BINDINGS:
                    return

    rec(0, {})
    rng.shuffle(results)
    return results


def _applications(recipe: Recipe, state: list[Fact], rng: random.Random, instance: str):
    """Yield (requires, provides, subst, facts_to_add) for each valid binding."""
    reqs = [rename_fact(f, instance) for f in recipe.requires]
    provs = [rename_fact(f, instance) for f in recipe.provides]
    for s in _bind_requires(reqs, state, rng):
        new: list[Fact] = [subst_fact(f, s) for f in provs]
        # assert the ports this recipe needs, so the inventory is complete
        for req in reqs:
            if req.pred == "open_port":
                new.append(subst_fact(req, s))
        merged = list(state)
        for f in new:
            if f not in merged:
                merged.append(f)
        yield reqs, provs, s, merged


def _search(
    state: list[Fact],
    used: set[str],
    depth_left: int,
    goal: str,
    rng: random.Random,
    recipes: list[Recipe],
    step_no: int,
) -> list[Step] | None:
    if depth_left == 0:
        return None

    if depth_left == 1:
        # the final step must be the one that yields the flag
        pool = [r for r in recipes if r.id not in used and goal in r.yields]
    else:
        # intermediate steps must not grab a flag early
        pool = [r for r in recipes if r.id not in used and not r.yields]

    rng.shuffle(pool)
    for recipe in pool:
        instance = f"{recipe.id}#{step_no}"
        for reqs, provs, subst, merged in _applications(recipe, state, rng, instance):
            step = Step(recipe, instance, subst, reqs, provs, merged)
            if depth_left == 1:
                return [step]
            rest = _search(merged, used | {recipe.id}, depth_left - 1, goal, rng, recipes, step_no + 1)
            if rest is not None:
                return [step, *rest]
    return None


def _useful_recipes(recipes: list[Recipe]) -> list[Recipe]:
    """Drop recipes whose facts no other recipe consumes.

    A discovery that only yields an unused fact (e.g. a VM smoke probe) can
    never be part of a causally relevant chain, so it is not a planner
    candidate. Recipes that yield a flag are always kept.
    """
    required = [f for r in recipes for f in r.requires if f.pred not in PRELUDE]
    useful: list[Recipe] = []
    for recipe in recipes:
        if recipe.yields:
            useful.append(recipe)
            continue
        if any(
            unify_fact(provided, needed, {}) is not None
            for provided in recipe.provides
            for needed in required
        ):
            useful.append(recipe)
    return useful


def generate(
    recipes: list[Recipe],
    os_name: str,
    to_user: int,
    to_root: int,
    seed: int,
    prefix: list[Step] | None = None,
    machine_difficulty: str | None = None,
    user_difficulty: str | None = None,
    root_difficulty: str | None = None,
) -> Plan | None:
    if to_user < 1 or to_root < 1:
        raise ValueError("to_user and to_root must both be >= 1")
    if prefix is not None and len(prefix) > to_user:
        raise ValueError("prefix cannot be longer than to_user")
    recipes = _useful_recipes(recipes)
    rng = random.Random(seed)
    for _ in range(MAX_ATTEMPTS):
        if prefix:
            steps = list(prefix)
            state = prefix[-1].state
            used = {s.recipe.id for s in prefix}
            remaining_user = to_user - len(prefix)
            step_no = len(prefix)
        else:
            steps = []
            state = initial_state(os_name)
            used = set()
            remaining_user = to_user
            step_no = 0

        if remaining_user > 0:
            user_steps = _search(state, used, remaining_user, "user", rng, recipes, step_no)
            if user_steps is None:
                continue
            steps = steps + user_steps
            used = used | {s.recipe.id for s in user_steps}
            state = user_steps[-1].state

        root_steps = _search(state, used, to_root, "root", rng, recipes, to_user)
        if root_steps is None:
            continue
        plan = Plan(os_name=os_name, steps=[*steps, *root_steps], seed=seed)
        if is_relevant(plan) and difficulty_mod.matches(
            plan,
            machine=machine_difficulty,
            user=user_difficulty,
            root=root_difficulty,
        ):
            return plan
    return None


def generate_paths(
    recipes: list[Recipe],
    os_name: str,
    to_user: int,
    to_root: int,
    seed: int,
    count: int,
    share_prefix: bool = True,
    machine_difficulty: str | None = None,
    user_difficulty: str | None = None,
    root_difficulty: str | None = None,
) -> list[Plan]:
    """Generate up to ``count`` distinct paths.

    With ``share_prefix`` the user phase of the previous path is reused, so the
    paths form a DAG with a shared prefix and different root branches.
    """
    if count < 2:
        raise ValueError("multi-path needs at least 2 paths")
    paths: list[Plan] = []
    seen: set[tuple[str, ...]] = set()
    for index in range(count):
        prefix = None
        if share_prefix and paths and len(paths[-1].steps) >= to_user:
            prefix = paths[-1].steps[:to_user]

        found = False
        for attempt in range(50):
            if index == 0 and attempt == 0:
                path_seed = seed
            else:
                path_seed = derive_seed(seed, "path", str(index), str(attempt))
            plan = generate(
                recipes,
                os_name,
                to_user,
                to_root,
                path_seed,
                prefix=prefix,
                machine_difficulty=machine_difficulty,
                user_difficulty=user_difficulty,
                root_difficulty=root_difficulty,
            )
            if plan is None:
                continue
            key = tuple(step.recipe.id for step in plan.steps)
            if key in seen:
                continue
            seen.add(key)
            paths.append(plan)
            found = True
            break

        if not found and prefix is not None:
            # no distinct branch with the shared prefix; fall back to independent
            for attempt in range(50):
                path_seed = derive_seed(seed, "path", str(index), "solo", str(attempt))
                plan = generate(
                    recipes,
                    os_name,
                    to_user,
                    to_root,
                    path_seed,
                    machine_difficulty=machine_difficulty,
                    user_difficulty=user_difficulty,
                    root_difficulty=root_difficulty,
                )
                if plan is None:
                    continue
                key = tuple(step.recipe.id for step in plan.steps)
                if key in seen:
                    continue
                seen.add(key)
                paths.append(plan)
                break
    return paths


def _effective_provides(step: Step) -> set[Fact]:
    return {
        subst_fact(f, step.subst) for f in step.provides if f.pred not in PRELUDE
    }


def _effective_requires(step: Step) -> set[Fact]:
    return {
        subst_fact(f, step.subst) for f in step.requires if f.pred not in PRELUDE
    }


def is_relevant(plan: Plan) -> bool:
    """True if every step lies on a dependency path to a flag.

    Edges are built from *actual* fact sharing (after each step's substitution),
    not mere unifiability, so a redundant producer whose fact nobody really
    consumed is not counted as an ancestor. Adjacency is not required: a plan
    may fan out from one step and merge later, as long as no step is a dead end.
    """
    steps = plan.steps
    if not steps:
        return False
    goals = {i for i, s in enumerate(steps) if s.recipe.yields}
    if not goals:
        return False

    producers: list[list[int]] = [[] for _ in steps]
    for i, step in enumerate(steps):
        provided = _effective_provides(step)
        if not provided:
            continue
        for j in range(i + 1, len(steps)):
            if provided & _effective_requires(steps[j]):
                producers[j].append(i)

    seen = set(goals)
    stack = list(goals)
    while stack:
        j = stack.pop()
        for i in producers[j]:
            if i not in seen:
                seen.add(i)
                stack.append(i)
    return len(seen) == len(steps)


def satisfies(plan: Plan) -> bool:
    """Re-simulate the plan using the bindings the planner actually chose.

    Recomputing a fresh first application is not equivalent: a step can have
    several valid bindings, and the one chosen for the plan is what later
    steps depend on. This walks the recorded substitutions and verifies each
    requirement against the state produced by the planned chain.
    """
    state = initial_state(plan.os_name)
    for step in plan.steps:
        reqs = [subst_fact(f, step.subst) for f in step.requires]
        for req in reqs:
            if req in state:
                continue
            # open_port preconditions are free in the planner; they become part
            # of the machine's service inventory rather than a state fact.
            if (
                req.pred == "open_port"
                and len(req.args) == 2
                and req.args[0] == TARGET
            ):
                continue
            return False
        provided = [subst_fact(f, step.subst) for f in step.provides]
        new = [*provided, *(req for req in reqs if req.pred == "open_port")]
        for fact in new:
            if fact not in state:
                state.append(fact)
    return True
