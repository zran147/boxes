"""Per-recipe test harness.

A recipe is a unit: given a state that satisfies its ``requires``, applying it
must produce its ``provides`` with every variable grounded. This module checks
that symbolically -- no machine, no VM.

The :class:`Fixture` it emits is deliberately the *bridge to P1*: it is the
minimal concrete input a recipe needs, so the same fixture can later drive a
minimal-repro VM and a real PoC run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from random import Random

from .facts import Fact, Var, SIGNATURES
from .lint import lint
from .manifest import generate_param
from .values import format_value
from .planner import PRELUDE, TARGET, _applications, initial_state
from .recipe import Recipe

SAMPLE_OS = "ubuntu-22.04"
SAMPLE_OSES = ["ubuntu-22.04", "ubuntu-24.04", "debian-12", "rocky-9"]
_PLACEHOLDER = re.compile(r"\{([A-Za-z0-9_.]+)\}")
_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")


@dataclass
class Fixture:
    recipe_id: str
    os: str
    params: dict
    requires: list[str]
    provides: list[str]
    walkthrough: str
    context: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "recipe": self.recipe_id,
            "os": self.os,
            "params": self.params,
            "requires": self.requires,
            "provides": self.provides,
            "context": self.context,
            "walkthrough": self.walkthrough,
        }


@dataclass
class Result:
    recipe_id: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    fixture: Fixture | None = None

    @property
    def ok(self) -> bool:
        return not self.errors


def _ground(term, ctx: dict):
    """Ground a fact term from a recipe's concrete context."""
    if isinstance(term, Var):
        return ctx.get(term.name, f"fixture_{term.name}")
    return term


def _ground_fact(f: Fact, ctx: dict) -> Fact:
    return Fact(f.pred, tuple(_ground(a, ctx) for a in f.args))


def _resolve_provides(provides, subst: dict, instance: str, params: dict):
    """Ground a renamed, substituted provides fact. Returns (fact, ok)."""

    def walk(t):
        seen: set[str] = set()
        while isinstance(t, Var) and t.name in subst and t.name not in seen:
            seen.add(t.name)
            t = subst[t.name]
        return t

    def resolve(t):
        t = walk(t)
        if isinstance(t, Var):
            name = t.name
            if name.startswith(f"{instance}."):
                base = name[len(instance) + 1 :]
                if base in params:
                    return params[base]
            return None
        return t

    out = []
    ok = True
    for f in provides:
        args = tuple(resolve(a) for a in f.args)
        if any(a is None for a in args):
            ok = False
        out.append(Fact(f.pred, args))
    return out, ok


def _render(template: str, ctx: dict) -> str:
    return _PLACEHOLDER.sub(
        lambda m: format_value(ctx[m.group(1)]) if m.group(1) in ctx else m.group(0),
        template,
    )


def check_recipe(recipe: Recipe, seed: int = 0, os_name: str | None = None) -> Result:
    result = Result(recipe_id=recipe.id)
    rng = Random(seed)

    if not _ID.match(recipe.id):
        result.errors.append(f"recipe id must match {_ID.pattern!r}")
    if not recipe.provides:
        result.errors.append("recipe must declare at least one provides fact")
    if os_name is not None:
        if not recipe.applies_to(os_name):
            result.errors.append(
                f"recipe os {recipe.os} does not apply to {os_name}"
            )
            return result
    else:
        os_name = next((o for o in SAMPLE_OSES if recipe.applies_to(o)), None)
        if os_name is None:
            result.errors.append(
                f"recipe os {recipe.os} matches none of the sample OSes {SAMPLE_OSES}"
            )
            return result

    result.errors.extend(lint([recipe]))

    used_users: set[str] = set()
    params = {
        name: generate_param(spec, rng, used_users)
        for name, spec in recipe.params.items()
    }

    # A complete concrete context for this recipe in isolation. Variables that
    # would normally come from a sibling recipe are grounded to fixture_<name>,
    # so provisioning and PoCs share one source of truth.
    ctx = dict(params)
    for f in [*recipe.requires, *recipe.provides]:
        for a in f.args:
            if isinstance(a, Var):
                base = a.name
                ctx.setdefault(base, TARGET if base == "h" else f"fixture_{base}")

    grounded_requires = [_ground_fact(f, ctx) for f in recipe.requires]
    state = initial_state(os_name) + grounded_requires

    instance = f"{recipe.id}#1"
    apps = list(_applications(recipe, state, rng, instance))
    if not apps:
        result.errors.append("recipe is not applicable in a state that satisfies its requires")
        return result

    _, provides, subst, _ = apps[0]
    grounded_provides, ok = _resolve_provides(provides, subst, instance, params)
    if not ok:
        result.errors.append(f"provides contain ungrounded variables: {', '.join(str(p) for p in provides)}")
    for f in grounded_provides:
        if f.pred not in SIGNATURES:
            result.errors.append(f"unknown predicate {f.pred!r}")

    text = _render(recipe.walkthrough, ctx)
    leftovers = _PLACEHOLDER.findall(text)
    if leftovers:
        result.errors.append(f"walkthrough has unresolved placeholder(s): {sorted(set(leftovers))}")

    # Negative test: without its non-prelude requirements the recipe must not apply.
    non_prelude = [f for f in grounded_requires if f.pred not in PRELUDE]
    if not non_prelude:
        result.warnings.append(
            "no negative test: recipe only has prelude requirements "
            "(legitimate for a recipe that only needs network exposure)"
        )
    else:
        reduced = [f for f in grounded_requires if f is not non_prelude[0]]
        reduced_state = initial_state(os_name) + reduced
        if list(_applications(recipe, reduced_state, Random(seed), instance)):
            result.errors.append(
                f"recipe still applies without its requirement {non_prelude[0]} (guard is ineffective)"
            )

    result.fixture = Fixture(
        recipe_id=recipe.id,
        os=os_name,
        params=params,
        requires=[str(f) for f in grounded_requires],
        provides=[str(f) for f in grounded_provides],
        walkthrough=text,
        context=ctx,
    )
    return result


def check_all(recipes: list[Recipe], seed: int = 0) -> list[Result]:
    return [check_recipe(r, seed) for r in recipes]
