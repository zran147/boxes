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
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from uuid import uuid4

from .backends.base import Backend, ExecResult
from .cache import Cache, recipe_key
from .images import attacker_image
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
    cached: bool = False
    attacker: str | None = None

    def add(self, step: StepResult) -> None:
        self.steps.append(step)
        if not step.ok:
            self.ok = False


def _container_name(prefix: str, label: str) -> str:
    safe = _SAFE.sub("-", label)[:32].strip("-") or "x"
    return f"boxes-{prefix}-{safe}-{uuid4().hex[:8]}"


def _env_key(name: str) -> str:
    return "BOX_" + re.sub(r"[^A-Za-z0-9]", "_", name).upper()


def build_env(recipe: Recipe, ctx: dict, os_name: str, host: str = "127.0.0.1") -> dict[str, str]:
    env = {_env_key(key): str(value) for key, value in ctx.items()}
    # reserved keys always win over a recipe param with the same name
    env["BOX_RECIPE"] = recipe.id
    env["BOX_OS"] = os_name
    env["BOX_ASSETS"] = f"/opt/boxes/{recipe.id}"
    env["BOX_HOST"] = host
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
    host: str = "127.0.0.1",
) -> ExecResult:
    try:
        script = recipe.script(phase).read_text()
    except (OSError, ValueError) as e:
        return ExecResult(2, "", str(e))
    return backend.exec(
        container,
        script,
        user=user,
        env=build_env(recipe, ctx, os_name, host=host),
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


def _copy_assets(backend: Backend, container: str, recipe: Recipe) -> ExecResult:
    if not recipe.assets:
        return ExecResult(0, "", "")
    dest = f"/opt/boxes/{recipe.id}"
    mk = backend.exec(container, f"mkdir -p '{dest}'", user=None, timeout=30)
    if not mk.ok:
        return mk
    return backend.put(container, f"{recipe.assets_dir}/.", dest)


def _create(
    backend: Backend,
    container: str,
    image: str,
    network: str = "none",
    alias: str | None = None,
) -> str | None:
    res = backend.create(container, image, network=network, alias=alias)
    if res.ok:
        return None
    return f"could not create container: {res.output()}"


def _network_name(prefix: str) -> str:
    return f"boxes-net-{prefix}-{uuid4().hex[:10]}"


def _attacker_for(recipe: Recipe) -> bool:
    return getattr(recipe, "poc_context", "target") == "attacker"


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

    needs_attacker = _attacker_for(recipe)
    network = _network_name("recipe")
    target = _container_name("target", recipe.id)
    attacker = _container_name("attacker", recipe.id) if needs_attacker else None
    result.container = target
    result.attacker = attacker
    result.kept = keep

    net_res = backend.network_create(network)
    if not net_res.ok:
        result.ok = False
        result.error = f"could not create network: {net_res.output()}"
        return result
    err = _create(backend, target, image, network=network, alias="target")
    if err:
        backend.network_destroy(network)
        result.ok = False
        result.error = err
        return result
    if attacker is not None:
        err = _create(backend, attacker, attacker_image(), network=network)
        if err:
            backend.destroy(target)
            backend.network_destroy(network)
            result.ok = False
            result.error = err
            return result

    try:
        ctx = dict(fixture.context)
        ctx.setdefault("os", fixture.os)
        assets = _copy_assets(backend, target, recipe)
        result.add(_to_step(recipe, "assets", assets))
        prov = _run_script(
            backend, target, recipe, "provision", ctx, fixture.os, None, PROVISION_TIMEOUT
        )
        result.add(_to_step(recipe, "provision", prov))
        if prov.ok:
            if needs_attacker:
                extra = _copy_assets(backend, attacker, recipe)
                if not extra.ok:
                    result.add(_to_step(recipe, "assets", extra))
                poc = _run_script(
                    backend, attacker, recipe, "poc", ctx, fixture.os,
                    "attacker", recipe.poc_timeout, host="target",
                )
                result.add(_to_step(recipe, "poc", poc, actor="attacker"))
            else:
                actor, actor_err = _actor_or_error(recipe, ctx)
                if actor_err:
                    result.add(StepResult(recipe.id, "poc", False, exit_code=2, output=actor_err))
                else:
                    poc = _run_script(
                        backend, target, recipe, "poc", ctx, fixture.os,
                        actor, recipe.poc_timeout, host="127.0.0.1",
                    )
                    result.add(_to_step(recipe, "poc", poc, actor=actor))
    finally:
        if not keep:
            if attacker is not None:
                backend.destroy(attacker)
            backend.destroy(target)
            backend.network_destroy(network)
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

    needs_attacker = any(_attacker_for(s.recipe) for s in plan.steps)
    network = _network_name("machine")
    target = _container_name("machine", f"seed-{plan.seed}")
    attacker = _container_name("attacker", f"seed-{plan.seed}") if needs_attacker else None
    result.container = target
    result.attacker = attacker
    result.kept = keep

    net_res = backend.network_create(network)
    if not net_res.ok:
        result.ok = False
        result.error = f"could not create network: {net_res.output()}"
        return result
    err = _create(backend, target, image, network=network, alias="target")
    if err:
        backend.network_destroy(network)
        result.ok = False
        result.error = err
        return result
    if attacker is not None:
        err = _create(backend, attacker, attacker_image(), network=network)
        if err:
            backend.destroy(target)
            backend.network_destroy(network)
            result.ok = False
            result.error = err
            return result

    contexts = []
    try:
        for step in plan.steps:
            ctx = dict(manifest.step_context(step))
            ctx.setdefault("os", plan.os_name)
            contexts.append(ctx)
            assets = _copy_assets(backend, target, step.recipe)
            result.add(_to_step(step.recipe, "assets", assets))
            res = _run_script(
                backend, target, step.recipe, "provision", ctx, plan.os_name, None, PROVISION_TIMEOUT
            )
            result.add(_to_step(step.recipe, "provision", res))

        for step, ctx in zip(plan.steps, contexts):
            if _attacker_for(step.recipe):
                # one shared attacker container serves every attacker-context PoC
                extra = _copy_assets(backend, attacker, step.recipe)
                if not extra.ok:
                    result.add(_to_step(step.recipe, "assets", extra))
                res = _run_script(
                    backend, attacker, step.recipe, "poc", ctx, plan.os_name,
                    "attacker", step.recipe.poc_timeout, host="target",
                )
                result.add(_to_step(step.recipe, "poc", res, actor="attacker"))
                continue

            actor, actor_err = _actor_or_error(step.recipe, ctx)
            if actor_err:
                result.add(
                    StepResult(step.recipe.id, "poc", False, exit_code=2, output=actor_err)
                )
                continue
            res = _run_script(
                backend, target, step.recipe, "poc", ctx, plan.os_name,
                actor, step.recipe.poc_timeout, host="127.0.0.1",
            )
            result.add(_to_step(step.recipe, "poc", res, actor=actor))
    finally:
        if not keep:
            if attacker is not None:
                backend.destroy(attacker)
            backend.destroy(target)
            backend.network_destroy(network)
    return result


def verify_recipes(
    pairs: list[tuple[Recipe, object]],
    backend: Backend,
    image: str,
    image_id: str = "",
    jobs: int = 1,
    cache: Cache | None = None,
    keep: bool = False,
) -> list[VerifyResult]:
    """Verify several recipes, using the cache and up to ``jobs`` containers.

    Results are returned in input order regardless of completion order.
    """
    fidelity = _backend_fidelity(backend)
    items = [
        (recipe, fixture, recipe_key(recipe, fixture.context, image_id, fidelity))
        for recipe, fixture in pairs
    ]

    results: list[VerifyResult | None] = [None] * len(items)
    todo: list[int] = []
    for index, (recipe, fixture, key) in enumerate(items):
        hit = cache.get(key) if cache else None
        if hit is not None:
            results[index] = VerifyResult(label=recipe.id, ok=True, cached=True)
        else:
            todo.append(index)

    def run(index: int) -> VerifyResult:
        recipe, fixture, _ = items[index]
        return verify_recipe(recipe, fixture, backend, image, keep=keep)

    if jobs <= 1:
        for index in todo:
            results[index] = run(index)
    elif todo:
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            for index, result in zip(todo, pool.map(run, todo)):
                results[index] = result

    for index in todo:
        result = results[index]
        if cache is not None and result is not None and result.ok:
            cache.put(items[index][2], {"recipe": items[index][0].id})

    return [r for r in results if r is not None]
