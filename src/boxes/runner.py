"""Build and verify machines on a backend.

Two levels, mirroring the verification hierarchy:

* **L2 / minimal repro** -- :func:`verify_recipe` builds a throwaway container,
  runs one recipe's ``provision`` (as root) then its ``poc`` (as the actor), and
  tears it down. Recipes therefore prove themselves in isolation.
* **L3 / chain** -- :func:`verify_machine` provisions every step in order, then
  runs every PoC in order. This tests composability, not just individual recipes.

PoC contract: a script that exits 0 on success. Provisioning and PoC both get
the grounded values in the environment as ``BOX_<KEY>`` (e.g. ``BOX_U``,
``BOX_BINARY``), plus ``BOX_RECIPE`` and ``BOX_OS``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from uuid import uuid4

from .backends.base import Backend, ExecResult
from .manifest import Manifest
from .planner import Plan
from .recipe import Recipe

PROVISION_TIMEOUT = 300
_SAFE = re.compile(r"[^A-Za-z0-9_.-]")


@dataclass
class StepResult:
    recipe: str
    phase: str  # "provision" | "poc"
    ok: bool
    exit_code: int = 0
    output: str = ""
    actor: str | None = None


@dataclass
class VerifyResult:
    label: str
    ok: bool = True
    steps: list[StepResult] = field(default_factory=list)
    container: str | None = None
    error: str | None = None
    kept: bool = False

    def add(self, step: StepResult) -> None:
        self.steps.append(step)
        if not step.ok:
            self.ok = False


def _container_name(prefix: str, label: str) -> str:
    safe = _SAFE.sub("-", label)[:40].strip("-") or "x"
    return f"boxes-{prefix}-{safe}-{uuid4().hex[:8]}"


def _env_key(name: str) -> str:
    return "BOX_" + re.sub(r"[^A-Za-z0-9]", "_", name).upper()


def build_env(recipe: Recipe, ctx: dict, os_name: str) -> dict[str, str]:
    env = {_env_key(key): str(value) for key, value in ctx.items()}
    # reserved keys always win over a recipe param with the same name
    env["BOX_RECIPE"] = recipe.id
    env["BOX_OS"] = os_name
    return env


def resolve_actor(recipe: Recipe, ctx: dict) -> str:
    actor = recipe.actor or "attacker"
    if actor.startswith("$"):
        key = actor[1:]
        if key not in ctx:
            raise ValueError(f"{recipe.id}: actor {actor} is not bound in this context")
        return str(ctx[key])
    return actor


def _actor_or_error(recipe: Recipe, ctx: dict) -> tuple[str | None, str | None]:
    try:
        return resolve_actor(recipe, ctx), None
    except ValueError as e:
        return None, str(e)


def _backend_fidelity(backend: Backend) -> str:
    return getattr(backend, "fidelity", "container")


def _run_script(
    backend: Backend,
    container: str,
    recipe: Recipe,
    phase: str,
    ctx: dict,
    os_name: str,
    user: str | None,
    timeout: int,
) -> ExecResult:
    try:
        script = recipe.script(phase).read_text()
    except (OSError, ValueError) as e:
        return ExecResult(2, "", str(e))
    return backend.exec(
        container,
        script,
        user=user,
        env=build_env(recipe, ctx, os_name),
        timeout=timeout,
    )


def _to_step(recipe: Recipe, phase: str, res: ExecResult, actor: str | None = None) -> StepResult:
    return StepResult(
        recipe=recipe.id,
        phase=phase,
        ok=res.ok,
        exit_code=res.exit_code,
        output=res.output(),
        actor=actor,
    )


def _create(backend: Backend, container: str, image: str) -> str | None:
    res = backend.create(container, image)
    if res.ok:
        return None
    return f"could not create container: {res.output()}"


def verify_recipe(
    recipe: Recipe,
    fixture,
    backend: Backend,
    image: str,
    keep: bool = False,
) -> VerifyResult:
    result = VerifyResult(label=recipe.id)
    if not recipe.verifiable:
        result.ok = False
        result.error = "recipe has no provision/poc scripts (symbolic-only)"
        return result
    if recipe.fidelity != _backend_fidelity(backend):
        result.ok = False
        result.error = (
            f"recipe needs a {recipe.fidelity} backend, "
            f"but {backend.name} is {_backend_fidelity(backend)}"
        )
        return result

    container = _container_name("recipe", recipe.id)
    result.container = container
    result.kept = keep
    err = _create(backend, container, image)
    if err:
        result.ok = False
        result.error = err
        return result

    try:
        ctx = dict(fixture.context)
        ctx.setdefault("os", fixture.os)
        prov = _run_script(
            backend, container, recipe, "provision", ctx, fixture.os, None, PROVISION_TIMEOUT
        )
        result.add(_to_step(recipe, "provision", prov))
        if prov.ok:
            actor, actor_err = _actor_or_error(recipe, ctx)
            if actor_err:
                result.add(StepResult(recipe.id, "poc", False, exit_code=2, output=actor_err))
            else:
                poc = _run_script(
                    backend, container, recipe, "poc", ctx, fixture.os, actor, recipe.poc_timeout
                )
                result.add(_to_step(recipe, "poc", poc, actor=actor))
    finally:
        if not keep:
            backend.destroy(container)
    return result


def verify_machine(
    plan: Plan,
    manifest: Manifest,
    backend: Backend,
    image: str,
    keep: bool = False,
) -> VerifyResult:
    label = f"machine seed={plan.seed}"
    result = VerifyResult(label=label)

    missing = [s.recipe.id for s in plan.steps if not s.recipe.verifiable]
    if missing:
        result.ok = False
        result.error = f"recipes without provision/poc: {', '.join(missing)}"
        return result

    incompatible = [
        f"{s.recipe.id} ({s.recipe.fidelity})"
        for s in plan.steps
        if s.recipe.fidelity != _backend_fidelity(backend)
    ]
    if incompatible:
        result.ok = False
        result.error = (
            f"backend {backend.name} is {_backend_fidelity(backend)}; "
            f"incompatible recipes: {', '.join(incompatible)}"
        )
        return result

    container = _container_name("machine", f"seed-{plan.seed}")
    result.container = container
    result.kept = keep
    err = _create(backend, container, image)
    if err:
        result.ok = False
        result.error = err
        return result

    contexts = []
    try:
        for step in plan.steps:
            ctx = dict(manifest.step_context(step))
            ctx.setdefault("os", plan.os_name)
            contexts.append(ctx)
            res = _run_script(
                backend, container, step.recipe, "provision", ctx, plan.os_name, None, PROVISION_TIMEOUT
            )
            result.add(_to_step(step.recipe, "provision", res))

        for step, ctx in zip(plan.steps, contexts):
            actor, actor_err = _actor_or_error(step.recipe, ctx)
            if actor_err:
                result.add(
                    StepResult(step.recipe.id, "poc", False, exit_code=2, output=actor_err)
                )
                continue
            res = _run_script(
                backend, container, step.recipe, "poc", ctx, plan.os_name, actor, step.recipe.poc_timeout
            )
            result.add(_to_step(step.recipe, "poc", res, actor=actor))
    finally:
        if not keep:
            backend.destroy(container)
    return result
