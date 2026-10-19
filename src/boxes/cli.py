"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

from . import accel as accel_mod
from . import difficulty as difficulty_mod
from . import toolkit
from .backends import get_backend
from .cache import Cache, machine_key
from .harness import check_recipe
from .images import PROJECT_ROOT, attacker_image, ensure_attacker_image, ensure_image, image_tag
from .lint import lint
from .manifest import materialize
from .nethelper import (
    NetError,
    attach_attacker,
    down as net_down,
    provision_down,
    provision_tap,
    provision_tap_down,
    provision_up,
    up as net_up,
)
from .planner import generate, generate_paths, satisfies
from .registry import load_registry, select
from . import attest
from . import registry_client
from . import registry_server
from .registry_client import RegistryError
from .signing import SignatureError
from . import signing as registry_client_signing
from .runner import verify_machine, verify_paths, verify_recipes
from .scaffold import create_recipe
from .osinfo import SUPPORTED_OS, vm_store
from .vm_image import prepare_base
from .writeup import paths_to_dict, plan_to_dict, render_machine_markdown, render_markdown

DEFAULT_RECIPES = Path("recipes")
CACHE_FILE = PROJECT_ROOT / ".boxes-cache" / "verifications.json"


def _load_all_recipes(args) -> list:
    recipes = load_registry(args.recipes)
    installed_dir = registry_client.registry_recipes()
    if installed_dir.is_dir():
        installed = load_registry(installed_dir)
        local_ids = {r.id for r in recipes}
        for recipe in installed:
            if recipe.id in local_ids:
                raise ValueError(
                    f"recipe {recipe.id!r} is installed from a registry and also "
                    f"exists locally in {args.recipes}"
                )
        recipes = recipes + installed
    return recipes


def _untrusted_check(args, recipes) -> bool:
    untrusted = sorted({r.id for r in recipes if registry_client.is_registry_recipe(r)})
    if not untrusted:
        return True
    if args.backend == "qemu":
        print(
            "refusing QEMU verification of untrusted registry recipes: "
            + ", ".join(untrusted)
            + ". The VM sandbox milestone is not implemented yet; use --backend docker.",
            file=sys.stderr,
        )
        return False
    if getattr(args, "sandbox", None) == "trusted":
        print(
            "untrusted registry recipes require the locked Docker sandbox: "
            + ", ".join(untrusted)
            + ". Omit --sandbox (with --allow-untrusted) or pass --sandbox locked.",
            file=sys.stderr,
        )
        return False
    if not args.allow_untrusted:
        print(
            "untrusted registry recipes: "
            + ", ".join(untrusted)
            + ". Pass --allow-untrusted to run them in the locked Docker sandbox.",
            file=sys.stderr,
        )
        return False
    print(
        "warning: running untrusted registry recipes in the locked Docker sandbox; "
        "the isolated worker/attestation milestone is next: " + ", ".join(untrusted),
        file=sys.stderr,
    )
    return True


def _difficulty_note(args) -> str:
    parts = []
    for label, value in (
        ("machine", getattr(args, "difficulty", None)),
        ("user", getattr(args, "user_difficulty", None)),
        ("root", getattr(args, "root_difficulty", None)),
    ):
        if value:
            parts.append(f"{label} {value}")
    return f" (difficulty: {', '.join(parts)})" if parts else ""


def cmd_gen(args) -> int:
    recipes = _load_all_recipes(args)
    errs = lint(recipes)
    if errs:
        print("recipe lint failed:", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 2

    pool = select(recipes, args.os)
    if not pool:
        print(f"no recipes apply to os {args.os}", file=sys.stderr)
        return 2

    seed = args.seed if args.seed is not None else random.randrange(1, 2**31)
    build_seed = args.build_seed if args.build_seed is not None else random.randrange(1, 2**31)

    if args.multi_path is not None:
        if args.multi_path < 2:
            print("--multi-path needs at least 2 paths", file=sys.stderr)
            return 2
        paths = generate_paths(
            pool,
            args.os,
            args.to_user,
            args.to_root,
            seed,
            args.multi_path,
            machine_difficulty=args.difficulty,
            user_difficulty=args.user_difficulty,
            root_difficulty=args.root_difficulty,
        )
        if not paths:
            print(
                "could not generate any paths for those depths"
                + _difficulty_note(args),
                file=sys.stderr,
            )
            return 1
        if len(paths) < args.multi_path:
            print(
                f"note: only {len(paths)} distinct path(s) available",
                file=sys.stderr,
            )
        for path in paths:
            if not satisfies(path):
                print("internal error: generated path does not satisfy itself", file=sys.stderr)
                return 3
        manifests = [materialize(path, build_seed) for path in paths]
        if args.json:
            print(json.dumps(paths_to_dict(paths, manifests), indent=2))
        else:
            print(render_machine_markdown(paths, manifests))
        return 0

    plan = generate(
        pool,
        args.os,
        args.to_user,
        args.to_root,
        seed,
        machine_difficulty=args.difficulty,
        user_difficulty=args.user_difficulty,
        root_difficulty=args.root_difficulty,
    )
    if plan is None:
        print(
            f"could not build a machine with {args.to_user} step(s) to user and "
            f"{args.to_root} step(s) to root" + _difficulty_note(args),
            file=sys.stderr,
        )
        return 1

    if not satisfies(plan):
        print("internal error: generated plan does not satisfy itself", file=sys.stderr)
        return 3

    manifest = materialize(plan, build_seed)

    if args.json:
        print(json.dumps(plan_to_dict(plan, manifest), indent=2))
    else:
        print(render_markdown(plan, manifest))
    return 0


def cmd_recipes(args) -> int:
    recipes = _load_all_recipes(args)
    for r in sorted(recipes, key=lambda x: (x.kind, x.id)):
        flag = f"  yields={','.join(r.yields)}" if r.yields else ""
        print(f"{r.id:32} {r.kind:14} v{r.version}  os={','.join(r.os)}{flag}")
    return 0


def cmd_lint(args) -> int:
    recipes = _load_all_recipes(args)
    errs = lint(recipes)
    if errs:
        for e in errs:
            print(f"FAIL {e}")
        return 1
    print(f"OK: {len(recipes)} recipe(s) passed lint")
    return 0


def cmd_test_recipe(args) -> int:
    recipes = _load_all_recipes(args)
    if args.all:
        targets = recipes
    elif args.id:
        targets = [r for r in recipes if r.id == args.id]
        if not targets:
            print(f"no such recipe: {args.id}", file=sys.stderr)
            return 2
    else:
        print("give a recipe id or --all", file=sys.stderr)
        return 2

    failed = 0
    for r in targets:
        res = check_recipe(r, args.seed)
        print(f"{'OK  ' if res.ok else 'FAIL'} {r.id}")
        for w in res.warnings:
            print(f"     warn: {w}")
        for e in res.errors:
            print(f"     error: {e}")
        if args.fixture and res.fixture is not None:
            print(json.dumps(res.fixture.to_dict(), indent=2))
        failed += 0 if res.ok else 1

    if len(targets) > 1:
        print(f"\n{len(targets) - failed}/{len(targets)} recipe(s) passed")
    return 1 if failed else 0


def cmd_new(args) -> int:
    try:
        path = create_recipe(args.recipes, args.id, args.kind, args.os, args.difficulty)
    except (ValueError, FileExistsError) as e:
        print(e, file=sys.stderr)
        return 2
    print(f"created {path}")

    recipes = _load_all_recipes(args)
    errs = lint(recipes)
    if errs:
        print("recipe lint failed after scaffold:", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 1

    res = check_recipe(next(r for r in recipes if r.id == args.id), args.seed)
    if not res.ok:
        for e in res.errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(f"OK: {args.id} passes lint and the recipe harness")
    return 0


def _print_verify(result) -> None:
    if result.cached:
        print(f"\n=== {result.label}: CACHED ===")
        return
    print(f"\n=== {result.label}: {'OK' if result.ok else 'FAIL'} ===")
    if result.error:
        print(f"  error: {result.error}")
    for s in result.steps:
        who = f" as {s.actor}" if s.actor else ""
        print(f"  {s.phase:<9} {s.recipe:<28}{who}  {'OK' if s.ok else 'FAIL'}")
        if not s.ok and s.output:
            for line in s.output.splitlines():
                print(f"      {line}")
    if result.container and result.kept:
        print(f"  container kept: {result.container}")
    if result.attacker and result.kept:
        print(f"  attacker kept: {result.attacker}")


def _make_cache(args) -> Cache:
    cache = Cache(CACHE_FILE, enabled=not args.no_cache)
    if args.clear_cache:
        cache.clear()
        print("verification cache cleared")
    return cache


def _prepare_backend(args):
    if args.backend == "qemu":
        try:
            selected = accel_mod.resolve(getattr(args, "accel", None))
        except ValueError as e:
            print(str(e), file=sys.stderr)
            return None
        backend = get_backend("qemu", accel=selected, os_name=args.os)
    else:
        if args.backend == "docker":
            sandbox = getattr(args, "sandbox", None)
            if sandbox is None:
                sandbox = "locked" if getattr(args, "allow_untrusted", False) else "trusted"
            backend = get_backend("docker", sandbox=sandbox)
        else:
            backend = get_backend(args.backend)
    if not backend.available():
        print(f"backend {args.backend!r} is not available", file=sys.stderr)
        if args.backend == "qemu":
            print(
                "qemu needs qemu-system-x86_64, a pre-baked base image and an SSH key.\n"
                "run: boxes image build --backend qemu --os ubuntu-22.04",
                file=sys.stderr,
            )
        return None
    if args.backend == "qemu":
        # VM attacker-context PoCs use the Docker attacker image.
        docker = get_backend("docker")
        if docker.available():
            res = ensure_attacker_image(docker, getattr(args, "rebuild", False))
            if not res.ok:
                print("attacker image is not ready:", file=sys.stderr)
                print(res.output(), file=sys.stderr)
                return None
        return backend
    rebuild = getattr(args, "rebuild", False)
    for tag, ensure in (
        (image_tag(args.os), lambda: ensure_image(backend, args.os, rebuild)),
        (attacker_image(), lambda: ensure_attacker_image(backend, rebuild)),
    ):
        res = ensure()
        if not res.ok:
            print(f"image {tag} is not ready:", file=sys.stderr)
            print(res.output(), file=sys.stderr)
            return None
    return backend


def cmd_image(args) -> int:
    if args.backend == "qemu":
        if args.os not in SUPPORTED_OS:
            print(
                f"unsupported VM OS {args.os}; supported: {', '.join(SUPPORTED_OS)}",
                file=sys.stderr,
            )
            return 2
        try:
            selected = accel_mod.resolve(args.accel)
        except ValueError as e:
            print(str(e), file=sys.stderr)
            return 2
        res = prepare_base(
            vm_store(args.os),
            rebuild=args.rebuild,
            base=Path(os.environ["BOXES_VM_BASE"]) if os.environ.get("BOXES_VM_BASE") else None,
            accel=selected,
            os_name=args.os,
        )
        if not res.ok:
            print("VM base image prep failed:", file=sys.stderr)
            print(res.output(), file=sys.stderr)
            return 1
        print(res.stdout.strip() or "VM base image ready")
        docker = get_backend("docker")
        if docker.available():
            att = ensure_attacker_image(docker, args.rebuild)
            if not att.ok:
                print("attacker image build failed:", file=sys.stderr)
                print(att.output(), file=sys.stderr)
                return 1
            print(att.stdout.strip() or "attacker image ready")
        else:
            print(
                "note: Docker is unavailable; VM attacker-context PoCs need "
                "boxes/attacker:latest",
                file=sys.stderr,
            )
        return 0
    backend = _prepare_backend(args)
    if backend is None:
        return 2
    print(f"images ready: {image_tag(args.os)}, {attacker_image()}")
    return 0


def cmd_image_tools(args) -> int:
    print("apt: " + ", ".join(toolkit.apt_packages()))
    print("pip: " + (", ".join(toolkit.pip_packages()) or "(none)"))
    print("commands: " + ", ".join(sorted(toolkit.commands())))
    if not args.check:
        return 0

    import shlex
    import shutil
    import subprocess

    if not shutil.which("docker"):
        print("docker is not installed", file=sys.stderr)
        return 2
    script = "missing=\n"
    for command in sorted(toolkit.commands()):
        script += (
            f"command -v {shlex.quote(command)} >/dev/null 2>&1 "
            f'|| missing="$missing {command}"\n'
        )
    script += 'if [ -n "$missing" ]; then echo "missing:$missing" >&2; exit 1; fi\n'
    script += 'echo "toolkit ok"\n'
    res = subprocess.run(
        ["docker", "run", "--rm", attacker_image(), "sh", "-c", script],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if res.returncode != 0:
        print(res.stdout.strip())
        print(res.stderr.strip(), file=sys.stderr)
        return 1
    print(res.stdout.strip())
    return 0


def cmd_verify(args) -> int:
    if args.multi_path is not None:
        if not args.machine:
            print("--multi-path only applies to --machine", file=sys.stderr)
            return 2
        if args.multi_path < 2:
            print("--multi-path needs at least 2 paths", file=sys.stderr)
            return 2
    if any((args.difficulty, args.user_difficulty, args.root_difficulty)) and not args.machine:
        print("difficulty filters only apply to --machine", file=sys.stderr)
        return 2
    if args.attest_key and args.machine:
        print("attestations are per recipe; use --recipe or --all", file=sys.stderr)
        return 2
    if args.attest_key and not args.attestation_dir:
        args.attestation_dir = "attestations"
    if args.attestation_dir and not args.attest_key:
        print("--attestation-dir requires --attest-key", file=sys.stderr)
        return 2
    if args.attest_key:
        # An attestation must describe a fresh verification, not a cache hit.
        args.no_cache = True
    if args.backend == "qemu" and args.os not in SUPPORTED_OS:
        print(
            f"unsupported VM OS {args.os}; supported: {', '.join(SUPPORTED_OS)}",
            file=sys.stderr,
        )
        return 2
    from . import proxy as proxy_mod

    if not proxy_mod.services_ok():
        print(
            "warning: provisioning proxy is down or unhealthy; recipes that "
            "install packages will fail (run `boxes proxy up`)",
            file=sys.stderr,
        )
    backend = _prepare_backend(args)
    if backend is None:
        return 2
    if args.backend == "qemu":
        print(f"qemu accel={backend.accel}")
    image = image_tag(args.os)
    # QEMU targets use the VM base; attacker-context PoCs still use the Docker
    # attacker image, so include it in the cache identity for both backends.
    image_id = f"{backend.image_id(image)}|{backend.image_id(attacker_image())}"
    if args.apt_snapshot:
        image_id = f"{image_id}|apt-snapshot={args.apt_snapshot}"
    cache = _make_cache(args)

    if args.machine:
        recipes = _load_all_recipes(args)
        pool = select(recipes, args.os, fidelity=backend.fidelity)
        build_seed = args.build_seed if args.build_seed is not None else random.randrange(1, 2**31)

        if args.multi_path is not None:
            paths = generate_paths(
                pool,
                args.os,
                args.to_user,
                args.to_root,
                args.seed,
                args.multi_path,
                machine_difficulty=args.difficulty,
                user_difficulty=args.user_difficulty,
                root_difficulty=args.root_difficulty,
            )
            if not paths:
                print(
                "could not generate any paths for those depths"
                + _difficulty_note(args),
                file=sys.stderr,
            )
                return 1
            if len(paths) < args.multi_path:
                print(
                    f"note: only {len(paths)} distinct path(s) available",
                    file=sys.stderr,
                )
            if not _untrusted_check(args, [step.recipe for path in paths for step in path.steps]):
                return 2
            manifests = [materialize(path, build_seed) for path in paths]
            print(f"base plan seed={args.seed} build seed={build_seed} paths={len(paths)}")
            entries = []
            for index, (path, manifest) in enumerate(zip(paths, manifests), 1):
                if not satisfies(path):
                    print(f"internal error: path {index} does not satisfy itself", file=sys.stderr)
                    return 3
                summary = difficulty_mod.report(path)
                print(
                    f"path {index} (seed {path.seed}): "
                    + " -> ".join(s.recipe.id for s in path.steps)
                    + f"  [difficulty {summary['machine']}/10 ({summary['band']}); "
                    + f"user {summary['user']}/10 {summary['user_band']}; "
                    + f"root {summary['root']}/10 {summary['root_band']}]"
                )
                key = machine_key(path, manifest, image_id, backend.fidelity)
                entries.append((path, manifest, key, cache.get(key) is not None))

            todo = [entry for entry in entries if not entry[3]]
            ok = True
            if todo:
                results = verify_paths(
                    [entry[0] for entry in todo],
                    [entry[1] for entry in todo],
                    backend,
                    image,
                    keep=args.keep,
                    apt_snapshot=args.apt_snapshot,
                )
                for (path, manifest, key, _), result in zip(todo, results):
                    _print_verify(result)
                    if result.ok:
                        cache.put(key, {"plan_seed": path.seed, "build_seed": build_seed})
                    ok = ok and result.ok
            for index, (path, manifest, key, hit) in enumerate(entries, 1):
                if hit:
                    print(f"path {index} already verified (cache hit)")
            return 0 if ok else 1

        plan = generate(
            pool,
            args.os,
            args.to_user,
            args.to_root,
            args.seed,
            machine_difficulty=args.difficulty,
            user_difficulty=args.user_difficulty,
            root_difficulty=args.root_difficulty,
        )
        if plan is None:
            print(
                "could not generate a machine for those depths"
                + _difficulty_note(args),
                file=sys.stderr,
            )
            return 1
        if not satisfies(plan):
            print("internal error: generated plan does not satisfy itself", file=sys.stderr)
            return 3
        if not _untrusted_check(args, [step.recipe for step in plan.steps]):
            return 2
        manifest = materialize(plan, build_seed)
        print(f"plan seed={args.seed} build seed={build_seed}")
        print("chain: " + " -> ".join(s.recipe.id for s in plan.steps))
        summary = difficulty_mod.report(plan)
        print(
            f"difficulty: {summary['machine']}/10 ({summary['band']}; "
            f"user {summary['user']}/10 {summary['user_band']}, "
            f"root {summary['root']}/10 {summary['root_band']})"
        )

        key = machine_key(plan, manifest, image_id, backend.fidelity)
        if cache.get(key) is not None:
            print("machine already verified (cache hit)")
            return 0

        result = verify_machine(plan, manifest, backend, image, keep=args.keep, apt_snapshot=args.apt_snapshot)
        _print_verify(result)
        if result.ok:
            cache.put(key, {"plan_seed": plan.seed, "build_seed": build_seed})
        return 0 if result.ok else 1

    recipes = _load_all_recipes(args)
    if args.all:
        targets = recipes
    elif args.recipe:
        targets = [r for r in recipes if r.id == args.recipe]
        if not targets:
            print(f"no such recipe: {args.recipe}", file=sys.stderr)
            return 2
    else:
        print("give --recipe <id>, --all, or --machine", file=sys.stderr)
        return 2

    pairs = []
    harness_failures = 0
    for r in targets:
        if not r.verifiable:
            print(f"SKIP {r.id} (symbolic only: no provision/poc)")
            continue
        if not r.applies_to(args.os):
            print(f"SKIP {r.id} (does not apply to {args.os})")
            continue
        if not r.supports(backend.fidelity):
            print(f"SKIP {r.id} (no PoC for the {backend.fidelity} backend)")
            continue
        fixture = check_recipe(r, args.seed, os_name=args.os).fixture
        if fixture is None:
            print(f"FAIL {r.id}: harness produced no fixture", file=sys.stderr)
            harness_failures += 1
            continue
        pairs.append((r, fixture))

    if not pairs:
        print("no verifiable recipes", file=sys.stderr)
        return 1
    if not _untrusted_check(args, [recipe for recipe, _fixture in pairs]):
        return 2

    started_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    results = verify_recipes(
        pairs,
        backend,
        image,
        image_id=image_id,
        jobs=args.jobs,
        cache=cache,
        keep=args.keep,
        apt_snapshot=args.apt_snapshot,
    )
    for result in results:
        _print_verify(result)
    if args.attest_key:
        finished_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        for (recipe, _fixture), result in zip(pairs, results):
            if not result.ok:
                continue
            body = attest.build(
                recipe,
                result,
                image_id=image_id,
                os_name=args.os,
                backend=backend.fidelity,
                sandbox=getattr(backend, "sandbox", "vm"),
                apt_snapshot=args.apt_snapshot,
                started_at=started_at,
                finished_at=finished_at,
            )
            signed = attest.sign(body, args.attest_key)
            path = attest.write(signed, args.attestation_dir)
            print(f"attestation: {path}")

    ok = sum(1 for r in results if r.ok)
    total = len(results) + harness_failures
    cached = sum(1 for r in results if r.cached)
    suffix = f" ({cached} cached)" if cached else ""
    print(f"\n{ok}/{total} recipe(s) verified{suffix}")
    return 0 if harness_failures == 0 and ok == len(results) else 1


def cmd_registry(args) -> int:
    try:
        if args.registry_command == "keygen":
            info = registry_client_signing.keygen(args.out)
            print(f"private: {info['private']}")
            print(f"public:  {info['public']}")
            print(f"fingerprint: {info['fingerprint']}")
            return 0
        if args.registry_command == "add":
            reg = registry_client.add_registry(args.name, args.url, args.key)
            print(f"added {args.name}: {reg['url']}")
            print(f"operator fingerprint: {reg['operator_fingerprint']}")
            print(f"index sequence: {reg['sequence']}")
            return 0
        if args.registry_command == "remove":
            registry_client.remove_registry(args.name)
            print(f"removed registry {args.name}")
            return 0
        if args.registry_command == "list":
            for reg in registry_client.list_registries():
                print(
                    f"{reg['name']:16} {reg['url']}  "
                    f"seq={reg['sequence']}  key={reg['operator_fingerprint'][:16]}"
                )
            for item in registry_client.installed():
                print(
                    f"  installed {item['id']}@{item['version']} "
                    f"from {item['registry']}"
                )
            return 0
        if args.registry_command == "search":
            for entry in registry_client.search(args.query, args.registry):
                meta = entry.get("metadata", {})
                print(
                    f"{entry['id']}@{entry['version']}  "
                    f"publisher={entry['publisher']}  "
                    f"difficulty={meta.get('difficulty')}  "
                    f"os={','.join(meta.get('os', []))}"
                )
                if meta.get("description"):
                    print(f"  {meta['description']}")
            return 0
        if args.registry_command == "install":
            rid = args.spec.split("@", 1)[0]
            local_ids = set()
            if Path(args.recipes).is_dir():
                local_ids = {r.id for r in load_registry(args.recipes)}
            if rid in local_ids:
                print(
                    f"refusing to install {rid!r}: it collides with a local recipe; "
                    "registry namespaces are the next registry milestone",
                    file=sys.stderr,
                )
                return 2
            entry = registry_client.install(
                args.spec, args.registry, force=args.force,
                require_attestation=args.require_attestation,
            )
            print(f"installed {entry['id']}@{entry['version']} from {entry['publisher']}")
            print(f"bundle: {entry['bundle']}")
            if entry.get("attestation"):
                print("attested: yes")
            return 0
        if args.registry_command == "update":
            changed = registry_client.update(
                args.registry, require_attestation=args.require_attestation
            )
            if not changed:
                print("nothing to update")
            for entry in changed:
                print(f"updated {entry['id']}@{entry['version']}")
            return 0
        if args.registry_command == "uninstall":
            registry_client.uninstall(args.id)
            print(f"uninstalled {args.id}")
            return 0
        if args.registry_command == "verify":
            results = registry_client.verify_installed(offline=args.offline)
            if not results:
                print("no installed registry recipes")
            failed = False
            for result in results:
                if args.require_attestation and not result.get("attested"):
                    result["errors"].append("attestation is required")
                if result["errors"]:
                    failed = True
                    print(f"FAIL {result['id']}@{result['version']}")
                    for error in result["errors"]:
                        print(f"  {error}")
                else:
                    suffix = " (attested)" if result.get("attested") else ""
                    print(f"OK   {result['id']}@{result['version']}{suffix}")
            return 1 if failed else 0
        if args.registry_command == "serve":
            trusted = set()
            for key_path in args.trust_publisher or []:
                trusted.add(registry_client_signing.fingerprint(
                    registry_client_signing.load_public(key_path)
                ))
            print(
                f"serving {Path(args.directory).resolve()} on "
                f"http://{args.bind}:{args.port} "
                f"({'read/write' if args.operator_key else 'read-only'})"
            )
            try:
                registry_server.serve(
                    args.directory, args.bind, args.port,
                    args.operator_key, trusted or None,
                )
            except KeyboardInterrupt:
                pass
            return 0
        if args.registry_command == "publish":
            if bool(args.url) == bool(args.registry_dir):
                print("publish needs exactly one of --registry-dir or --url", file=sys.stderr)
                return 2
            if args.url:
                result = registry_client.publish_api(
                    args.url, args.recipe_dir, args.publisher, args.key, args.attestation
                )
                print(f"published to {args.url}")
                print(f"index sequence: {result.get('sequence')}")
            else:
                index = registry_client.publish(
                    args.recipe_dir,
                    args.registry_dir,
                    args.publisher,
                    args.key,
                    args.operator_key,
                    args.attestation,
                )
                print(f"published to {Path(args.registry_dir) / 'index.json'}")
                print(f"index sequence: {index['sequence']}")
            return 0
    except (RegistryError, SignatureError, FileNotFoundError, ValueError) as e:
        print(f"registry error: {e}", file=sys.stderr)
        return 1
    return 2


def cmd_net(args) -> int:
    try:
        if args.net_command == "up":
            print(json.dumps(net_up(args.name, args.attacker_pid, args.user, args.vm_ip, args.attacker_ip)))
        elif args.net_command == "down":
            print(json.dumps(net_down(args.name)))
        elif args.net_command == "provision-up":
            print(json.dumps(provision_up(args.proxy_pid)))
        elif args.net_command == "provision-down":
            print(json.dumps(provision_down()))
        elif args.net_command == "provision-tap":
            if args.down:
                print(json.dumps(provision_tap_down(args.name)))
            else:
                print(json.dumps(provision_tap(args.name, args.user)))
        elif args.net_command == "attach-attacker":
            print(json.dumps(attach_attacker(args.name, args.attacker_pid)))
    except NetError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_proxy(args) -> int:
    from . import proxy as proxy_mod

    if args.proxy_command == "up":
        res = proxy_mod.up(rebuild=args.rebuild)
    elif args.proxy_command == "down":
        res = proxy_mod.down(clean=args.clean)
    elif args.proxy_command == "clean":
        res = proxy_mod.down(clean=True)
    elif args.proxy_command == "status":
        print(json.dumps(proxy_mod.status(), indent=2))
        return 0
    else:
        return 2
    if not res.ok:
        print("proxy operation failed:", file=sys.stderr)
        print(res.output(), file=sys.stderr)
        return 1
    print(res.stdout.strip() or "ok")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="boxes", description="HTB-style machine generator")
    p.add_argument("--recipes", default=str(DEFAULT_RECIPES), help="recipe directory")
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("gen", help="generate a machine plan")
    g.add_argument("--os", default="ubuntu-22.04")
    g.add_argument("--to-user", type=int, default=3, dest="to_user")
    g.add_argument("--to-root", type=int, default=2, dest="to_root")
    g.add_argument("--difficulty", choices=["easy", "medium", "hard"], default=None,
                   help="required machine difficulty (the hardest recipe)")
    g.add_argument("--user-difficulty", choices=["easy", "medium", "hard"], default=None,
                   dest="user_difficulty")
    g.add_argument("--root-difficulty", choices=["easy", "medium", "hard"], default=None,
                   dest="root_difficulty")
    g.add_argument("--seed", type=int, default=None, help="plan/chain seed")
    g.add_argument("--build-seed", type=int, default=None, dest="build_seed",
                   help="param materialisation seed (defaults to random)")
    g.add_argument("--multi-path", nargs="?", type=int, const=2, default=None,
                   dest="multi_path",
                   help="EXPERIMENTAL: generate N independent paths (default 2)")
    g.add_argument("--json", action="store_true")
    g.set_defaults(func=cmd_gen)

    r = sub.add_parser("recipes", help="list recipes")
    r.set_defaults(func=cmd_recipes)

    l = sub.add_parser("lint", help="validate recipes")
    l.set_defaults(func=cmd_lint)

    t = sub.add_parser("test-recipe", help="test one recipe (or all) in isolation")
    t.add_argument("id", nargs="?", help="recipe id")
    t.add_argument("--all", action="store_true", help="test every recipe")
    t.add_argument("--seed", type=int, default=0)
    t.add_argument("--fixture", action="store_true", help="print the grounded fixture")
    t.set_defaults(func=cmd_test_recipe)

    n = sub.add_parser("new", help="scaffold a new recipe")
    n.add_argument("id")
    n.add_argument("--kind", required=True,
                   choices=["discovery", "service-access", "creds", "foothold", "privesc"])
    n.add_argument("--os", action="append", help="OS pattern (repeatable), default ubuntu-*")
    n.add_argument("--difficulty", choices=["easy", "medium", "hard"], default="medium")
    n.add_argument("--seed", type=int, default=0)
    n.set_defaults(func=cmd_new)

    img = sub.add_parser("image", help="manage base images")
    img_sub = img.add_subparsers(dest="image_command", required=True)
    ib = img_sub.add_parser("build", help="build the base image")
    ib.add_argument("--os", default="ubuntu-22.04")
    ib.add_argument("--rebuild", action="store_true")
    ib.add_argument("--backend", default="docker", choices=["docker", "qemu"])
    ib.add_argument("--accel", choices=["auto", "kvm", "tcg"], default=None,
                    help="QEMU acceleration (default: $BOXES_QEMU_ACCEL or auto)")
    ib.set_defaults(func=cmd_image)
    it = img_sub.add_parser("tools", help="list or check the attacker toolkit")
    it.add_argument("--check", action="store_true", help="run the commands in boxes/attacker")
    it.set_defaults(func=cmd_image_tools)

    v = sub.add_parser("verify", help="build and verify recipes or a machine")
    v.add_argument("--recipe", help="verify one recipe in isolation (L2)")
    v.add_argument("--all", action="store_true", help="verify every verifiable recipe")
    v.add_argument("--machine", action="store_true", help="build and verify a full chain (L3)")
    v.add_argument("--seed", type=int, default=0)
    v.add_argument("--build-seed", type=int, default=None, dest="build_seed",
                   help="param materialisation seed (defaults to --seed)")
    v.add_argument("--multi-path", nargs="?", type=int, const=2, default=None,
                   dest="multi_path",
                   help="EXPERIMENTAL: verify N independent paths (default 2)")
    v.add_argument("--to-user", type=int, default=1, dest="to_user")
    v.add_argument("--to-root", type=int, default=1, dest="to_root")
    v.add_argument("--difficulty", choices=["easy", "medium", "hard"], default=None,
                   help="required machine difficulty (the hardest recipe)")
    v.add_argument("--user-difficulty", choices=["easy", "medium", "hard"], default=None,
                   dest="user_difficulty")
    v.add_argument("--root-difficulty", choices=["easy", "medium", "hard"], default=None,
                   dest="root_difficulty")
    v.add_argument("--os", default="ubuntu-22.04")
    v.add_argument("--backend", default="docker", choices=["docker", "qemu"])
    v.add_argument("--accel", choices=["auto", "kvm", "tcg"], default=None,
                   help="QEMU acceleration (default: $BOXES_QEMU_ACCEL or auto)")
    v.add_argument("--keep", action="store_true", help="keep the container for debugging")
    v.add_argument("--allow-untrusted", action="store_true", dest="allow_untrusted",
                   help="run registry-installed recipes in the locked Docker sandbox (QEMU is refused)")
    v.add_argument("--sandbox", choices=["trusted", "locked"], default=None,
                   help="Docker sandbox profile; untrusted recipes require locked")
    v.add_argument("--attest-key", default=None, dest="attest_key",
                   help="sign a per-recipe verification attestation with this private key")
    v.add_argument("--attestation-dir", default=None, dest="attestation_dir",
                   help="directory for signed attestations (default: attestations)")
    v.add_argument("--jobs", type=int, default=min(4, os.cpu_count() or 1),
                   help="parallel containers when verifying --all")
    v.add_argument("--apt-snapshot", default=None, dest="apt_snapshot",
                   help="pin apt to a snapshot timestamp, e.g. 20240101T000000Z")
    v.add_argument("--no-cache", action="store_true", dest="no_cache",
                   help="ignore and do not write the verification cache")
    v.add_argument("--clear-cache", action="store_true", dest="clear_cache",
                   help="clear the verification cache before running")
    v.set_defaults(func=cmd_verify)

    net = sub.add_parser("net", help="privileged VM network helper (run with sudo)")
    net_sub = net.add_subparsers(dest="net_command", required=True)
    nu = net_sub.add_parser("up", help="create bridge + tap + attacker veth")
    nu.add_argument("name")
    nu.add_argument("--attacker-pid", type=int, required=True, dest="attacker_pid")
    nu.add_argument("--user", default=None, help="user that owns the tap (default: SUDO_USER)")
    nu.add_argument("--vm-ip", default="10.66.1.2", dest="vm_ip")
    nu.add_argument("--attacker-ip", default="10.66.1.3", dest="attacker_ip")
    nu.set_defaults(func=cmd_net)
    nd = net_sub.add_parser("down", help="remove bridge + tap + veth")
    nd.add_argument("name")
    nd.set_defaults(func=cmd_net)
    pu = net_sub.add_parser("provision-up", help="attach the proxy to br-provision")
    pu.add_argument("proxy_pid", type=int)
    pu.set_defaults(func=cmd_net)
    pd = net_sub.add_parser("provision-down", help="detach the proxy from br-provision")
    pd.set_defaults(func=cmd_net)
    pt = net_sub.add_parser("provision-tap", help="create/remove a VM provisioning tap")
    pt.add_argument("name")
    pt.add_argument("--user", default=None)
    pt.add_argument("--down", action="store_true")
    pt.set_defaults(func=cmd_net)
    aa = net_sub.add_parser("attach-attacker", help="attach a recreated attacker to an attack bridge")
    aa.add_argument("name")
    aa.add_argument("attacker_pid", type=int)
    aa.set_defaults(func=cmd_net)

    px = sub.add_parser("proxy", help="package proxy/cache for provisioning")
    px_sub = px.add_subparsers(dest="proxy_command", required=True)
    pu = px_sub.add_parser("up", help="build/start the proxy and attach it")
    pu.add_argument("--rebuild", action="store_true")
    pu.set_defaults(func=cmd_proxy)
    pd = px_sub.add_parser("down", help="stop the proxy")
    pd.add_argument("--clean", action="store_true")
    pd.set_defaults(func=cmd_proxy)
    ps = px_sub.add_parser("status", help="show proxy status")
    ps.set_defaults(func=cmd_proxy)
    pc = px_sub.add_parser("clean", help="stop the proxy and wipe the cache")
    pc.set_defaults(func=cmd_proxy)

    rg = sub.add_parser("registry", help="signed recipe registry")
    rg_sub = rg.add_subparsers(dest="registry_command", required=True)

    rk = rg_sub.add_parser("keygen", help="generate an Ed25519 key pair")
    rk.add_argument("--out", required=True, help="output prefix (<out>.key/<out>.pub)")
    rk.set_defaults(func=cmd_registry)

    ra = rg_sub.add_parser("add", help="add and trust a signed static registry")
    ra.add_argument("name")
    ra.add_argument("url", help="registry directory or http(s) URL")
    ra.add_argument("--key", required=True, help="registry operator public key")
    ra.set_defaults(func=cmd_registry)

    rr = rg_sub.add_parser("remove", help="remove a registry configuration")
    rr.add_argument("name")
    rr.set_defaults(func=cmd_registry)

    rl = rg_sub.add_parser("list", help="list registries and installed recipes")
    rl.set_defaults(func=cmd_registry)

    rs = rg_sub.add_parser("search", help="search a verified registry index")
    rs.add_argument("query")
    rs.add_argument("--registry", default=None)
    rs.set_defaults(func=cmd_registry)

    ri = rg_sub.add_parser("install", help="install a pinned recipe bundle")
    ri.add_argument("spec", help="id or id@version")
    ri.add_argument("--registry", default=None)
    ri.add_argument("--force", action="store_true")
    ri.add_argument("--require-attestation", action="store_true", dest="require_attestation")
    ri.set_defaults(func=cmd_registry)

    ru = rg_sub.add_parser("update", help="update installed recipes")
    ru.add_argument("--registry", default=None)
    ru.add_argument("--require-attestation", action="store_true", dest="require_attestation")
    ru.set_defaults(func=cmd_registry)

    run = rg_sub.add_parser("uninstall", help="remove an installed recipe")
    run.add_argument("id")
    run.set_defaults(func=cmd_registry)

    rv = rg_sub.add_parser("verify", help="verify installed bundles and the signed index")
    rv.add_argument("--offline", action="store_true", help="verify only the lock and files")
    rv.add_argument("--require-attestation", action="store_true", dest="require_attestation")
    rv.set_defaults(func=cmd_registry)

    rp = rg_sub.add_parser("publish", help="publish a recipe to a static registry")
    rp.add_argument("recipe_dir")
    rp.add_argument("--registry-dir", default=None, dest="registry_dir")
    rp.add_argument("--url", default=None, help="publish through the registry HTTP API")
    rp.add_argument("--publisher", required=True)
    rp.add_argument("--key", required=True, help="publisher private key")
    rp.add_argument("--operator-key", default=None, dest="operator_key",
                    help="operator private key (defaults to --key)")
    rp.add_argument("--attestation", default=None,
                    help="signed verification attestation JSON")
    rp.set_defaults(func=cmd_registry)

    rv = rg_sub.add_parser("serve", help="serve a static registry over HTTP")
    rv.add_argument("directory")
    rv.add_argument("--bind", default="127.0.0.1")
    rv.add_argument("--port", type=int, default=8000)
    rv.add_argument("--operator-key", default=None, dest="operator_key",
                    help="enable POST /v1/publish and sign indexes with this key")
    rv.add_argument("--trust-publisher", action="append", default=None,
                    dest="trust_publisher",
                    help="public key allowed to publish (repeatable)")
    rv.set_defaults(func=cmd_registry)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, FileNotFoundError, yaml.YAMLError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
