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

import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from uuid import uuid4

from .backends.base import Backend, ExecResult
from .cache import Cache, recipe_key
from .images import attacker_image
from .manifest import Manifest
from .planner import Plan
from .proxy import APT_PROXY_PORT, ARTIFACT_PORT, PROXY_IP, PROXY_PORT
from . import proxy as proxy_mod
from .recipe import Recipe

PROVISION_TIMEOUT = int(os.environ.get("BOXES_PROVISION_TIMEOUT", "1200"))
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


def build_env(
    recipe: Recipe,
    ctx: dict,
    os_name: str,
    host: str = "127.0.0.1",
    proxy_url: str | None = None,
) -> dict[str, str]:
    env = {_env_key(key): str(value) for key, value in ctx.items()}
    # reserved keys always win over a recipe param with the same name
    env["BOX_RECIPE"] = recipe.id
    env["BOX_OS"] = os_name
    env["BOX_ASSETS"] = f"/opt/boxes/{recipe.id}"
    env["BOX_HOST"] = host
    if proxy_url:
        env["BOX_PROXY_URL"] = proxy_url
        env["http_proxy"] = proxy_url
        env["https_proxy"] = proxy_url
        env["HTTP_PROXY"] = proxy_url
        env["HTTPS_PROXY"] = proxy_url
        env["no_proxy"] = "localhost,127.0.0.1"
        env["NO_PROXY"] = "localhost,127.0.0.1"
        base = proxy_url.rsplit(":", 1)[0]
        env["BOX_ARTIFACTS_URL"] = f"{base}:{ARTIFACT_PORT}"
        env["BOX_APT_PROXY"] = f"http://{base}:{APT_PROXY_PORT}"
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
    proxy_url: str | None = None,
) -> ExecResult:
    try:
        script = recipe.script(phase).read_text()
    except (OSError, ValueError) as e:
        return ExecResult(2, "", str(e))
    return backend.exec(
        container,
        script,
        user=user,
        env=build_env(recipe, ctx, os_name, host=host, proxy_url=proxy_url),
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
    provision: bool = False,
) -> str | None:
    res = backend.create(container, image, network=network, alias=alias, provision=provision)
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
    provision: bool = False
    proxy_url: str | None = None
    apt_proxy_url: str | None = None
    apt_snapshot: str | None = None

def _setup(
    backend: Backend,
    label: str,
    image: str,
    needs_attacker: bool,
    keep: bool,
    apt_snapshot: str | None = None,
) -> tuple[_Setup | None, str | None]:
    vm = _backend_fidelity(backend) == "vm"
    proxy_up = proxy_mod.is_up()
    provision = proxy_up
    proxy_url = None
    apt_proxy_url = None
    if proxy_up:
        proxy_url = (
            f"http://{PROXY_IP}:{PROXY_PORT}" if vm
            else f"http://boxes-proxy:{PROXY_PORT}"
        )
        apt_proxy_url = (
            f"http://{PROXY_IP}:{APT_PROXY_PORT}" if vm
            else f"http://boxes-proxy:{APT_PROXY_PORT}"
        )
    setup = _Setup(
        target=_container_name("target", label),
        network=_network_name(label) if (needs_attacker or not vm) else None,
        attacker=_container_name("attacker", label) if needs_attacker else None,
        attacker_backend=_attacker_backend(backend) if needs_attacker else None,
        kept=keep,
        provision=provision,
        proxy_url=proxy_url,
        apt_proxy_url=apt_proxy_url,
        apt_snapshot=apt_snapshot,
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
        provision=setup.provision,
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


def _configure_apt(backend: Backend, setup: _Setup, result: VerifyResult) -> None:
    """Point apt at the durable proxy and optionally pin a snapshot date.

    apt gets its own proxy (apt-cacher-ng) while pip/curl keep the general
    squid proxy. The optional snapshot rewrites the distro sources, then
    refreshes the indexes once so later provisioning hits the cache.
    """
    if not setup.provision or not setup.proxy_url or not setup.apt_proxy_url:
        return
    config = [
        f'Acquire::http::Proxy "{setup.apt_proxy_url}";',
        f'Acquire::https::Proxy "{setup.proxy_url}";',
    ]
    if setup.apt_snapshot:
        # snapshot.ubuntu.com redirects HTTP to HTTPS; apt-cacher-ng mishandles
        # the by-hash files after that redirect, so send snapshot hosts to
        # squid (which does CONNECT) and use HTTPS sources below.
        for host in ("snapshot.ubuntu.com", "snapshot.debian.org"):
            config.append(f'Acquire::http::Proxy::{host} "{setup.proxy_url}";')
            config.append(f'Acquire::https::Proxy::{host} "{setup.proxy_url}";')
    script = (
        "set -eu\n"
        "mkdir -p /etc/apt/apt.conf.d\n"
        "cat > /etc/apt/apt.conf.d/01boxes <<'EOF'\n"
        + "\n".join(config)
        + "\nEOF\n"
    )
    if setup.apt_snapshot:
        snap = setup.apt_snapshot
        script += (
            ". /etc/os-release\n"
            'case "$ID" in\n'
            "  ubuntu)\n"
            "    cat > /etc/apt/sources.list <<EOF\n"
            f"deb https://snapshot.ubuntu.com/ubuntu/{snap}/ $VERSION_CODENAME main restricted universe multiverse\n"
            f"deb https://snapshot.ubuntu.com/ubuntu/{snap}/ $VERSION_CODENAME-updates main restricted universe multiverse\n"
            f"deb https://snapshot.ubuntu.com/ubuntu/{snap}/ $VERSION_CODENAME-security main restricted universe multiverse\n"
            "EOF\n"
            "    ;;\n"
            "  debian)\n"
            "    cat > /etc/apt/sources.list <<EOF\n"
            f"deb https://snapshot.debian.org/archive/debian/{snap}/ $VERSION_CODENAME main\n"
            f"deb https://snapshot.debian.org/archive/debian-security/{snap}/ $VERSION_CODENAME-security main\n"
            "EOF\n"
            "    ;;\n"
            "  *)\n"
            '    echo "no snapshot source for $ID" >&2; exit 1 ;;\n'
            "esac\n"
            "rm -f /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources\n"
            "apt-get update -qq\n"
        )
    res = backend.exec(setup.target, script, user=None, timeout=PROVISION_TIMEOUT)
    result.add(StepResult("machine", "apt-config", res.ok, res.exit_code, res.output()))


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
    apt_snapshot: str | None = None,
) -> VerifyResult:
    result = VerifyResult(label=recipe.id)
    if not recipe.verifiable:
        result.ok = False
        result.error = "recipe has no provision/poc scripts (symbolic-only)"
        return result
    if not recipe.supports(_backend_fidelity(backend)):
        result.ok = False
        result.error = (
            f"recipe has no PoC for the {_backend_fidelity(backend)} backend"
        )
        return result

    setup, err = _setup(backend, recipe.id, image, _attacker_for(recipe), keep, apt_snapshot=apt_snapshot)
    if setup is None:
        result.ok = False
        result.error = err
        return result
    result.container = setup.target
    result.attacker = setup.attacker
    result.kept = keep

    snapshot_ok = False
    try:
        _configure_apt(backend, setup, result)
        if not result.ok:
            return result
        ctx = dict(fixture.context)
        ctx.setdefault("os", fixture.os)
        assets = _copy_assets(backend, setup.target, recipe)
        result.add(_to_step(recipe, "assets", assets))
        prov = _run_script(
            backend, setup.target, recipe, "provision", ctx, fixture.os, None,
            PROVISION_TIMEOUT, proxy_url=setup.proxy_url,
        )
        result.add(_to_step(recipe, "provision", prov))
        if prov.ok:
            if setup.provision and hasattr(backend, "seal"):
                sealed = backend.seal(setup.target)
                result.add(
                    StepResult(recipe.id, "seal", sealed.ok, sealed.exit_code, sealed.output())
                )
            if hasattr(backend, "snapshot"):
                snap = backend.snapshot(setup.target, "pre-poc")
                result.add(
                    StepResult(recipe.id, "snapshot", snap.ok, snap.exit_code, snap.output())
                )
                snapshot_ok = snap.ok
            _poc(backend, setup, recipe, ctx, fixture.os, result)
    finally:
        if snapshot_ok and hasattr(backend, "restore"):
            rest = backend.restore(setup.target, "pre-poc")
            result.add(
                StepResult(recipe.id, "restore", rest.ok, rest.exit_code, rest.output())
            )
        _teardown(backend, setup, keep)
    return result


def verify_machine(
    plan: Plan,
    manifest: Manifest,
    backend: Backend,
    image: str,
    keep: bool = False,
    apt_snapshot: str | None = None,
) -> VerifyResult:
    result = VerifyResult(label=f"machine seed={plan.seed}")

    missing = [s.recipe.id for s in plan.steps if not s.recipe.verifiable]
    if missing:
        result.ok = False
        result.error = f"recipes without provision/poc: {', '.join(missing)}"
        return result

    incompatible = [
        f"{s.recipe.id} ({s.recipe.poc_backend})"
        for s in plan.steps
        if not s.recipe.supports(_backend_fidelity(backend))
    ]
    if incompatible:
        result.ok = False
        result.error = (
            f"backend {backend.name} is {_backend_fidelity(backend)}; "
            f"incompatible recipes: {', '.join(incompatible)}"
        )
        return result

    needs_attacker = any(_attacker_for(s.recipe) for s in plan.steps)
    setup, err = _setup(
        backend, f"seed-{plan.seed}", image, needs_attacker, keep, apt_snapshot=apt_snapshot
    )
    if setup is None:
        result.ok = False
        result.error = err
        return result
    result.container = setup.target
    result.attacker = setup.attacker
    result.kept = keep

    contexts = []
    snapshot_ok = False
    try:
        _configure_apt(backend, setup, result)
        if not result.ok:
            return result
        for step in plan.steps:
            ctx = dict(manifest.step_context(step))
            ctx.setdefault("os", plan.os_name)
            contexts.append(ctx)
            assets = _copy_assets(backend, setup.target, step.recipe)
            result.add(_to_step(step.recipe, "assets", assets))
            res = _run_script(
                backend, setup.target, step.recipe, "provision", ctx, plan.os_name, None,
                PROVISION_TIMEOUT, proxy_url=setup.proxy_url,
            )
            result.add(_to_step(step.recipe, "provision", res))

        if setup.provision and hasattr(backend, "seal"):
            sealed = backend.seal(setup.target)
            result.add(StepResult("machine", "seal", sealed.ok, sealed.exit_code, sealed.output()))

        if hasattr(backend, "snapshot"):
            snap = backend.snapshot(setup.target, "pre-poc")
            result.add(StepResult("machine", "snapshot", snap.ok, snap.exit_code, snap.output()))
            snapshot_ok = snap.ok

        for step, ctx in zip(plan.steps, contexts):
            _poc(backend, setup, step.recipe, ctx, plan.os_name, result)
    finally:
        if snapshot_ok and hasattr(backend, "restore"):
            rest = backend.restore(setup.target, "pre-poc")
            result.add(StepResult("machine", "restore", rest.ok, rest.exit_code, rest.output()))
        _teardown(backend, setup, keep)
    return result


def verify_paths(
    paths: list[Plan],
    manifests: list[Manifest],
    backend: Backend,
    image: str,
    keep: bool = False,
    apt_snapshot: str | None = None,
) -> list[VerifyResult]:
    """Verify multiple paths on one VM boot using snapshots.

    Falls back to one machine per path for containers or when a path needs an
    attacker-context PoC (attacker reset across paths is not wired yet).
    """
    fallback = (
        _backend_fidelity(backend) != "vm"
        or not hasattr(backend, "snapshot")
    )
    if fallback:
        return [
            verify_machine(path, manifest, backend, image, keep=keep, apt_snapshot=apt_snapshot)
            for path, manifest in zip(paths, manifests)
        ]

    needs_attacker = any(_attacker_for(s.recipe) for p in paths for s in p.steps)
    base_label = f"paths seed={paths[0].seed}"
    setup, err = _setup(
        backend, base_label, image, needs_attacker, keep, apt_snapshot=apt_snapshot
    )
    if setup is None:
        failed = VerifyResult(label=base_label)
        failed.ok = False
        failed.error = err
        return [failed for _ in paths]

    prefix_len = _common_prefix(paths)
    results = [VerifyResult(label=f"path seed={p.seed}") for p in paths]
    try:
        _configure_apt(backend, setup, results[0])
        if not results[0].ok:
            for result in results:
                result.ok = False
                result.error = "apt configuration failed"
            return results
        clean = backend.snapshot(setup.target, "clean")
        if not clean.ok:
            for result in results:
                result.ok = False
                result.error = f"could not snapshot clean state: {clean.output()}"
            return results

        # provision the shared prefix once
        if prefix_len:
            prefix_manifest = manifests[0]
            for step in paths[0].steps[:prefix_len]:
                ctx = dict(prefix_manifest.step_context(step))
                ctx.setdefault("os", paths[0].os_name)
                assets = _copy_assets(backend, setup.target, step.recipe)
                results[0].add(_to_step(step.recipe, "assets", assets))
                res = _run_script(
                    backend, setup.target, step.recipe, "provision", ctx,
                    paths[0].os_name, None, PROVISION_TIMEOUT,
                    proxy_url=setup.proxy_url,
                )
                results[0].add(_to_step(step.recipe, "provision", res))
            if not results[0].ok:
                for result in results:
                    result.ok = False
                    result.error = "shared prefix provisioning failed"
                return results

        shared = backend.snapshot(setup.target, "shared")
        if not shared.ok:
            for result in results:
                result.ok = False
                result.error = f"could not snapshot shared state: {shared.output()}"
            return results

        for index, (path, manifest) in enumerate(zip(paths, manifests), 1):
            result = results[index - 1]
            if index > 1:
                rest = backend.restore(setup.target, "shared")
                result.add(
                    StepResult("machine", "restore-shared", rest.ok, rest.exit_code, rest.output())
                )
                if not rest.ok:
                    continue
                if needs_attacker and setup.attacker is not None:
                    setup.attacker_backend.destroy(setup.attacker)
                    err = _create(
                        setup.attacker_backend, setup.attacker, attacker_image(), network="none"
                    )
                    if err:
                        result.add(StepResult("machine", "attacker-reset", False, 1, err))
                        continue
                    pid = getattr(setup.attacker_backend, "pid", lambda _n: 0)(setup.attacker)
                    att = (
                        backend.attach_attacker(setup.network, pid)
                        if hasattr(backend, "attach_attacker") and pid
                        else ExecResult(1, "", "backend cannot attach an attacker")
                    )
                    result.add(
                        StepResult("machine", "attacker-reset", att.ok, att.exit_code, att.output())
                    )
                    if not att.ok:
                        continue

            for step in path.steps[prefix_len:]:
                ctx = dict(manifest.step_context(step))
                ctx.setdefault("os", path.os_name)
                assets = _copy_assets(backend, setup.target, step.recipe)
                result.add(_to_step(step.recipe, "assets", assets))
                res = _run_script(
                    backend, setup.target, step.recipe, "provision", ctx, path.os_name, None,
                    PROVISION_TIMEOUT, proxy_url=setup.proxy_url,
                )
                result.add(_to_step(step.recipe, "provision", res))

            if setup.provision and hasattr(backend, "seal"):
                sealed = backend.seal(setup.target)
                result.add(
                    StepResult("machine", "seal", sealed.ok, sealed.exit_code, sealed.output())
                )

            snap = backend.snapshot(setup.target, "pre-poc")
            result.add(StepResult("machine", "snapshot", snap.ok, snap.exit_code, snap.output()))
            if snap.ok:
                for step in path.steps:
                    ctx = dict(manifest.step_context(step))
                    ctx.setdefault("os", path.os_name)
                    _poc(backend, setup, step.recipe, ctx, path.os_name, result)
                rest = backend.restore(setup.target, "pre-poc")
                result.add(
                    StepResult("machine", "restore", rest.ok, rest.exit_code, rest.output())
                )
    finally:
        _teardown(backend, setup, keep)
    return results


def _common_prefix(paths: list[Plan]) -> int:
    """Number of leading steps that are the same instances across all paths."""
    length = 0
    while all(len(path.steps) > length for path in paths):
        if len({path.steps[length].instance for path in paths}) != 1:
            break
        length += 1
    return length


def verify_recipes(
    pairs: list[tuple[Recipe, object]],
    backend: Backend,
    image: str,
    image_id: str = "",
    jobs: int = 1,
    cache: Cache | None = None,
    keep: bool = False,
    apt_snapshot: str | None = None,
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
        return verify_recipe(
            recipe, fixture, backend, image, keep=keep, apt_snapshot=apt_snapshot
        )

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
