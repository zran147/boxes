"""The planner.

A machine is a *plan*: an ordered chain of recipe applications where every
recipe's ``requires`` are satisfied by facts produced earlier. The plan has two
phases:

* **user phase** -- exactly ``to_user`` steps, the last of which is tagged
  ``yields: [user]`` (that step is what gets you the user flag).
* **root phase** -- exactly ``to_root`` further steps, the last tagged
  ``yields: [root]``.

``net.port`` preconditions are *free*: since nmap is a prelude and not a step,
a recipe requiring a port implicitly asserts that the machine exposes it. The
union of required ports becomes the machine's service inventory (the thing the
builder will install, and the thing we cap for coherence).
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from .facts import Fact, Var, rename_fact, subst_fact, unify_fact
from .recipe import Recipe

TARGET = "target"
MAX_ATTEMPTS = 2000
MAX_BINDINGS = 64

PRELUDE = {"net.port", "os", "host"}


@dataclass
class Step:
    recipe: Recipe
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
                if f.pred == "net.port" and len(f.args) == 2 and isinstance(f.args[1], int):
                    out.add(f.args[1])
        return sorted(out)


def initial_state(os_name: str) -> list[Fact]:
    return [Fact("os", (os_name,)), Fact("host", (TARGET,))]


def _candidate_facts(pat: Fact, state: list[Fact]) -> list[Fact]:
    """Facts in ``state`` that could satisfy ``pat`` (incl. assumed ports)."""
    out = [f for f in state if unify_fact(pat, f, {}) is not None]
    if pat.pred == "net.port" and len(pat.args) == 2:
        assumed = Fact("net.port", (TARGET, pat.args[1]))
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


def _applications(recipe: Recipe, state: list[Fact], rng: random.Random):
    """Yield (requires, provides, subst, facts_to_add) for each valid binding."""
    reqs = [rename_fact(f, recipe.id) for f in recipe.requires]
    provs = [rename_fact(f, recipe.id) for f in recipe.provides]
    for s in _bind_requires(reqs, state, rng):
        new: list[Fact] = [subst_fact(f, s) for f in provs]
        # assert the ports this recipe needs, so the inventory is complete
        for req in reqs:
            if req.pred == "net.port":
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
        for reqs, provs, subst, merged in _applications(recipe, state, rng):
            if depth_left == 1:
                return [Step(recipe, subst, reqs, provs, merged)]
            rest = _search(merged, used | {recipe.id}, depth_left - 1, goal, rng, recipes)
            if rest is not None:
                return [Step(recipe, subst, reqs, provs, merged), *rest]
    return None


def generate(
    recipes: list[Recipe],
    os_name: str,
    to_user: int,
    to_root: int,
    seed: int,
) -> Plan | None:
    if to_user < 1 or to_root < 1:
        raise ValueError("to_user and to_root must both be >= 1")

    rng = random.Random(seed)
    for _ in range(MAX_ATTEMPTS):
        state = initial_state(os_name)

        user_steps = _search(state, set(), to_user, "user", rng, recipes)
        if user_steps is None:
            continue
        used = {s.recipe.id for s in user_steps}
        mid_state = user_steps[-1].state

        root_steps = _search(mid_state, used, to_root, "root", rng, recipes)
        if root_steps is None:
            continue
        plan = Plan(os_name=os_name, steps=[*user_steps, *root_steps], seed=seed)
        if is_relevant(plan):
            return plan
    return None


def _consumes(prev_provides: list[Fact], cur_requires: list[Fact]) -> bool:
    for f in prev_provides:
        if f.pred in PRELUDE:
            continue
        for req in cur_requires:
            if req.pred in PRELUDE:
                continue
            if unify_fact(f, req, {}) is not None:
                return True
    return False


def is_relevant(plan: Plan) -> bool:
    """True if the plan is a *causal chain*.

    Every step must consume at least one fact the previous step produced (ports
    and OS facts are the free prelude and don't count). This is what stops the
    generator from padding depth with pointless discovery steps or with redundant
    parallel paths -- if a requested depth has no real chain, generation fails
    instead of emitting filler.
    """
    for i in range(1, len(plan.steps)):
        if not _consumes(plan.steps[i - 1].provides, plan.steps[i].requires):
            return False
    return True


def satisfies(plan: Plan) -> bool:
    """Re-simulate the plan and check every precondition was met in order."""
    state = initial_state(plan.os_name)
    for step in plan.steps:
        reqs = [rename_fact(f, step.recipe.id) for f in step.recipe.requires]
        subst: dict = {}
        for req in reqs:
            matched = None
            for f in state:
                ns = unify_fact(req, f, subst)
                if ns is not None:
                    matched = f
                    subst = ns
                    break
            if matched is None:
                # ports are assumed free
                if req.pred == "net.port" and len(req.args) == 2:
                    assumed = Fact("net.port", (TARGET, req.args[1]))
                    ns = unify_fact(req, assumed, subst)
                    if ns is None:
                        return False
                    subst = ns
                    state = state + [assumed]
                    continue
                return False
        for f in [rename_fact(x, step.recipe.id) for x in step.recipe.provides]:
            g = subst_fact(f, subst)
            if g not in state:
                state = state + [g]
    return True
