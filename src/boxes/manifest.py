"""The manifest: turn a plan's plan-variables into concrete values.

ctx keys (plan variables) are the *interface* between recipes; the manifest holds
the *values*. A variable produced by one recipe and consumed by another is the
same variable after unification, so it is grounded **once** here -- which is the
guarantee that a password leaked by the FTP recipe is exactly the password the
SSH account was configured with.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from .facts import Fact, Var
from .planner import Plan, Step
from .recipe import ParamSpec

_PW_CHARS = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


class _UF:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def add(self, x: str) -> None:
        self.parent.setdefault(x, x)

    def find(self, x: str) -> str:
        self.add(x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb

    def all(self) -> list[str]:
        return list(self.parent)


@dataclass
class Manifest:
    values: dict[str, object]  # var name -> grounded value
    uf: _UF

    def value_of(self, varname: str) -> object:
        return self.values.get(self.uf.find(varname), f"<{varname}>")

    def ground_term(self, t):
        if isinstance(t, Var):
            return self.value_of(t.name)
        return t

    def ground_fact(self, f: Fact) -> Fact:
        return Fact(f.pred, tuple(self.ground_term(a) for a in f.args))

    def step_context(self, step: Step) -> dict[str, object]:
        rid = step.recipe.id
        ctx: dict[str, object] = {}
        for name in step.recipe.params:
            ctx[name] = self.value_of(f"{rid}.{name}")
        for f in [*step.requires, *step.provides]:
            for a in f.args:
                if isinstance(a, Var) and a.name.startswith(f"{rid}."):
                    ctx[a.name[len(rid) + 1 :]] = self.value_of(a.name)
        return ctx


def _spec_for(plan: Plan, varname: str) -> ParamSpec | None:
    if "." not in varname:
        return None
    rid, base = varname.split(".", 1)
    for step in plan.steps:
        if step.recipe.id == rid:
            return step.recipe.params.get(base)
    return None


def generate_param(spec: ParamSpec, rng: random.Random):
    if spec.type == "choice":
        return rng.choice(list(spec.values or []))
    if spec.type == "password":
        return "".join(rng.choice(_PW_CHARS) for _ in range(spec.length))
    raise ValueError(f"unknown param type {spec.type!r}")


def materialize(plan: Plan, rng: random.Random) -> Manifest:
    uf = _UF()
    fixed_by_var: dict[str, object] = {}

    for step in plan.steps:
        rid = step.recipe.id
        for f in [*step.requires, *step.provides]:
            for v in _vars(f):
                uf.add(v)
        for pname in step.recipe.params:
            uf.add(f"{rid}.{pname}")

    for step in plan.steps:
        for k, v in step.subst.items():
            uf.add(k)
            if isinstance(v, Var):
                uf.add(v.name)
                uf.union(k, v.name)
            else:
                fixed_by_var[k] = v

    values: dict[str, object] = {}
    for varname in uf.all():
        root = uf.find(varname)
        if root in values:
            continue
        members = [v for v in uf.all() if uf.find(v) == root]
        fixed = next((fixed_by_var[m] for m in members if m in fixed_by_var), None)
        if fixed is not None:
            values[root] = fixed
            continue
        spec = next((_spec_for(plan, m) for m in members if _spec_for(plan, m) is not None), None)
        values[root] = generate_param(spec, rng) if spec is not None else None

    return Manifest(values=values, uf=uf)


def _vars(f: Fact) -> set[str]:
    return {a.name for a in f.args if isinstance(a, Var)}
