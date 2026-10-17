"""Build and verify machines on a backend.

Two levels, mirroring the verification hierarchy:

* **L2 / minimal repro** -- :func:`verify_recipe` builds a throwaway machine,
  runs one recipe's ``provision`` (as root) then its ``poc`` (as the actor), and
  tears it down.
* **L3 / chain** -- :func:`verify_machine` provisions every step in order, then
  runs every PoC in order.

PoC contexts:

* ``target`` runs inside the target, as the actor, with ``BOX_HOST=127.0.0.1``.
* ``attacker`` runs in the attacker container, with ``BOX_HOST`` set to the
  target's address on the shared network (``target`` for Docker, the tap IP for
  a VM).
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
    phase: str  # "assets" | "provision" | "poc"
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


def _attacker_backend(backend: Backend) -> Backend:
    """VM targets use a Docker attacker container on the shared tap network."""
    if _backend_fidelity(backend) == "vm":
        from .backends import get_backend

        return get_backend("docker")
    return backend


def _attacker_for(recipe: Recipe) -> bool:
    return getattr(recipe, "poc_context", "target") == "attacker"


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
    return f"could not create {container}: {res.output()}"


def _network_name(prefix: str) -> str:
    return f"boxes-net-{prefix}-{uuid4().hex[:10]}"


@dataclass
class _Setup:
    target: str
    network: str | None = None
    attacker: str | None = None
    attacker_backend: Backend | None = None
    host: str = "target"
    kept: bool = False


def _setup(
    backend: Backend,
    label: str,
    image: str,
    needs_attacker: bool,
    keep: bool,
) -> tuple[_Setup | None, str | None]:
    vm = _backend_fidelity(backend) == "vm"
    setup = _Setup(
        target=_container_name("target", label),
        network=_network_name(label) if (needs_attacker or not vm) else None,
        attacker=_container_name("attacker", label) if needs_attacker else None,
        attacker_backend=_attacker_backend(backend) if needs_attacker else None,
        kept=keep,
    )

    # VM: the attacker container must exist before `boxes net up` (it needs the
    # pid to move the veth into its netns), and the tap must exist before boot.
    if vm and needs_attacker:
        err = _create(setup.attacker_backend, setup.attacker, attacker_image(), network="none")
        if err:
            return None, err
        pid = getattr(setup.attacker_backend, "pid", lambda _n: 0)(setup.attacker)
        if not pid:
            setup.attacker_backend.destroy(setup.attacker)
            return None, f"could not determine the attacker container pid for {setup.attacker}"
        net_res = backend.network_create(setup.network, attacker_pid=pid)
        if not net_res.ok:
            setup.attacker_backend.destroy(setup.attacker)
            return None, (
                "warning: cannot set up VM attacker networking, so the "
                "attacker-context PoC cannot run and this recipe cannot be "
                f"verified. Run `boxes net up` via the sudoers rule. Detail: {net_res.output()}"
            )
        info = backend.network_info(setup.network) if hasattr(backend, "network_info") else {}
        setup.host = (info or {}).get("vm_ip", "target")
    else:
        if setup.network is not None:
            net_res = backend.network_create(setup.network)
            if not net_res.ok:
                return None, f"could not create network: {net_res.output()}"

    err = _create(
        backend,
        setup.target,
        image,
        network=setup.network or "none",
        alias="target" if setup.network else None,
    )
    if err:
        _teardown(backend, setup, keep=False)
        return None, err

    if needs_attacker and not vm:
        err = _create(backend, setup.attacker, attacker_image(), network=setup.network)
        if err:
            _teardown(backend, setup, keep=False)
            return None, err
    return setup, None


def _teardown(backend: Backend, setup: _Setup, keep: bool) -> None:
    if keep:
        return
    if setup.attacker is not None and setup.attacker_backend is not None:
        setup.attacker_backend.destroy(setup.attacker)
    backend.destroy(setup.target)
    if setup.network is not None:
        backend.network_destroy(setup.network)


def _poc(
    backend: Backend,
    setup: _Setup,
    recipe: Recipe,
    ctx: dict,
    os_name: str,
    result: VerifyResult,
) -> None:
    if _attacker_for(recipe):
        extra = _copy_assets(setup.attacker_backend, setup.attacker, recipe)
        if not extra.ok:
            result.add(_to_step(recipe, "assets", extra))
        res = _run_script(
            setup.attacker_backend,
            setup.attacker,
            recipe,
            "poc",
            ctx,
            os_name,
            "attacker",
            recipe.poc_timeout,
            host=setup.host,
        )
        result.add(_to_step(recipe, "poc", res, actor="attacker"))
        return

    actor, actor_err = _actor_or_error(recipe, ctx)
    if actor_err:
        result.add(StepResult(recipe.id, "poc", False, exit_code=2, output=actor_err))
        return
    res = _run_script(
        backend,
        setup.target,
        recipe,
        "poc",
        ctx,
        os_name,
        actor,
        recipe.poc_timeout,
        host="127.0.0.1",
    )
    result.add(_to_step(recipe, "poc", res, actor=actor))


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

    setup, err = _setup(backend, recipe.id, image, _attacker_for(recipe), keep)
    if setup is None:
        result.ok = False
        result.error = err
        return result
    result.container = setup.target
    result.attacker = setup.attacker
    result.kept = keep

    try:
        ctx = dict(fixture.context)
        ctx.setdefault("os", fixture.os)
        assets = _copy_assets(backend, setup.target, recipe)
        result.add(_to_step(recipe, "assets", assets))
        prov = _run_script(
            backend, setup.target, recipe, "provision", ctx, fixture.os, None, PROVISION_TIMEOUT
        )
        result.add(_to_step(recipe, "provision", prov))
        if prov.ok:
            _poc(backend, setup, recipe, ctx, fixture.os, result)
    finally:
        _teardown(backend, setup, keep)
    return result


def verify_machine(
    plan: Plan,
    manifest: Manifest,
    backend: Backend,
    image: str,
    keep: bool = False,
) -> VerifyResult:
    result = VerifyResult(label=f"machine seed={plan.seed}")

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
    setup, err = _setup(backend, f"seed-{plan.seed}", image, needs_attacker, keep)
    if setup is None:
        result.ok = False
        result.error = err
        return result
    result.container = setup.target
    result.attacker = setup.attacker
    result.kept = keep

    contexts = []
    try:
        for step in plan.steps:
            ctx = dict(manifest.step_context(step))
            ctx.setdefault("os", plan.os_name)
            contexts.append(ctx)
            assets = _copy_assets(backend, setup.target, step.recipe)
            result.add(_to_step(step.recipe, "assets", assets))
            res = _run_script(
                backend, setup.target, step.recipe, "provision", ctx, plan.os_name, None, PROVISION_TIMEOUT
            )
            result.add(_to_step(step.recipe, "provision", res))

        for step, ctx in zip(plan.steps, contexts):
            _poc(backend, setup, step.recipe, ctx, plan.os_name, result)
    finally:
        _teardown(backend, setup, keep)
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
    """Verify several recipes, using the cache and up to ``jobs`` machines."""
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
