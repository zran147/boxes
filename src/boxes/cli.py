"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from pathlib import Path

import yaml

from .backends import get_backend
from .cache import Cache, machine_key
from .harness import check_recipe
from .images import PROJECT_ROOT, attacker_image, ensure_attacker_image, ensure_image, image_tag
from .lint import lint
from .manifest import materialize
from .planner import generate, generate_paths, satisfies
from .registry import load_registry, select
from .runner import verify_machine, verify_recipes
from .scaffold import create_recipe
from .writeup import paths_to_dict, plan_to_dict, render_machine_markdown, render_markdown

DEFAULT_RECIPES = Path("recipes")
CACHE_FILE = PROJECT_ROOT / ".boxes-cache" / "verifications.json"


def cmd_gen(args) -> int:
    recipes = load_registry(args.recipes)
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
            pool, args.os, args.to_user, args.to_root, seed, args.multi_path
        )
        if not paths:
            print("could not generate any paths for those depths", file=sys.stderr)
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

    plan = generate(pool, args.os, args.to_user, args.to_root, seed)
    if plan is None:
        print(
            f"could not build a machine with {args.to_user} step(s) to user and "
            f"{args.to_root} step(s) to root",
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
    recipes = load_registry(args.recipes)
    for r in sorted(recipes, key=lambda x: (x.kind, x.id)):
        flag = f"  yields={','.join(r.yields)}" if r.yields else ""
        print(f"{r.id:32} {r.kind:14} v{r.version}  os={','.join(r.os)}{flag}")
    return 0


def cmd_lint(args) -> int:
    recipes = load_registry(args.recipes)
    errs = lint(recipes)
    if errs:
        for e in errs:
            print(f"FAIL {e}")
        return 1
    print(f"OK: {len(recipes)} recipe(s) passed lint")
    return 0


def cmd_test_recipe(args) -> int:
    recipes = load_registry(args.recipes)
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

    recipes = load_registry(args.recipes)
    errs = lint(recipes)
    if errs:
        print("registry lint failed after scaffold:", file=sys.stderr)
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
    backend = get_backend(args.backend)
    if not backend.available():
        print(f"backend {args.backend!r} is not available", file=sys.stderr)
        return None
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
    backend = _prepare_backend(args)
    if backend is None:
        return 2
    print(f"images ready: {image_tag(args.os)}, {attacker_image()}")
    return 0


def cmd_verify(args) -> int:
    if args.multi_path is not None:
        if not args.machine:
            print("--multi-path only applies to --machine", file=sys.stderr)
            return 2
        if args.multi_path < 2:
            print("--multi-path needs at least 2 paths", file=sys.stderr)
            return 2
    backend = _prepare_backend(args)
    if backend is None:
        return 2
    image = image_tag(args.os)
    image_id = f"{backend.image_id(image)}|{backend.image_id(attacker_image())}"
    cache = _make_cache(args)

    if args.machine:
        recipes = load_registry(args.recipes)
        pool = select(recipes, args.os)
        build_seed = args.build_seed if args.build_seed is not None else random.randrange(1, 2**31)

        if args.multi_path is not None:
            paths = generate_paths(
                pool, args.os, args.to_user, args.to_root, args.seed, args.multi_path
            )
            if not paths:
                print("could not generate any paths for those depths", file=sys.stderr)
                return 1
            if len(paths) < args.multi_path:
                print(
                    f"note: only {len(paths)} distinct path(s) available",
                    file=sys.stderr,
                )
            manifests = [materialize(path, build_seed) for path in paths]
            print(f"base plan seed={args.seed} build seed={build_seed} paths={len(paths)}")
            ok = True
            for index, (path, manifest) in enumerate(zip(paths, manifests), 1):
                if not satisfies(path):
                    print(f"internal error: path {index} does not satisfy itself", file=sys.stderr)
                    return 3
                print(f"path {index} (seed {path.seed}): " + " -> ".join(s.recipe.id for s in path.steps))
                key = machine_key(path, manifest, image_id, backend.fidelity)
                if cache.get(key) is not None:
                    print(f"path {index} already verified (cache hit)")
                    continue
                result = verify_machine(path, manifest, backend, image, keep=args.keep)
                _print_verify(result)
                if result.ok:
                    cache.put(key, {"plan_seed": path.seed, "build_seed": build_seed})
                ok = ok and result.ok
            return 0 if ok else 1

        plan = generate(pool, args.os, args.to_user, args.to_root, args.seed)
        if plan is None:
            print("could not generate a machine for those depths", file=sys.stderr)
            return 1
        if not satisfies(plan):
            print("internal error: generated plan does not satisfy itself", file=sys.stderr)
            return 3
        manifest = materialize(plan, build_seed)
        print(f"plan seed={args.seed} build seed={build_seed}")
        print("chain: " + " -> ".join(s.recipe.id for s in plan.steps))

        key = machine_key(plan, manifest, image_id, backend.fidelity)
        if cache.get(key) is not None:
            print("machine already verified (cache hit)")
            return 0

        result = verify_machine(plan, manifest, backend, image, keep=args.keep)
        _print_verify(result)
        if result.ok:
            cache.put(key, {"plan_seed": plan.seed, "build_seed": build_seed})
        return 0 if result.ok else 1

    recipes = load_registry(args.recipes)
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
        fixture = check_recipe(r, args.seed).fixture
        if fixture is None:
            print(f"FAIL {r.id}: harness produced no fixture", file=sys.stderr)
            harness_failures += 1
            continue
        pairs.append((r, fixture))

    if not pairs:
        print("no verifiable recipes", file=sys.stderr)
        return 1

    results = verify_recipes(
        pairs,
        backend,
        image,
        image_id=image_id,
        jobs=args.jobs,
        cache=cache,
        keep=args.keep,
    )
    for result in results:
        _print_verify(result)

    ok = sum(1 for r in results if r.ok)
    total = len(results) + harness_failures
    cached = sum(1 for r in results if r.cached)
    suffix = f" ({cached} cached)" if cached else ""
    print(f"\n{ok}/{total} recipe(s) verified{suffix}")
    return 0 if harness_failures == 0 and ok == len(results) else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="boxes", description="HTB-style machine generator (P0)")
    p.add_argument("--recipes", default=str(DEFAULT_RECIPES), help="recipe directory")
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("gen", help="generate a machine plan")
    g.add_argument("--os", default="ubuntu-22.04")
    g.add_argument("--to-user", type=int, default=3, dest="to_user")
    g.add_argument("--to-root", type=int, default=2, dest="to_root")
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
    n.add_argument("--difficulty", type=float, default=0.3)
    n.add_argument("--seed", type=int, default=0)
    n.set_defaults(func=cmd_new)

    img = sub.add_parser("image", help="manage base images")
    img_sub = img.add_subparsers(dest="image_command", required=True)
    ib = img_sub.add_parser("build", help="build the base image")
    ib.add_argument("--os", default="ubuntu-22.04")
    ib.add_argument("--rebuild", action="store_true")
    ib.add_argument("--backend", default="docker", choices=["docker"])
    ib.set_defaults(func=cmd_image)

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
    v.add_argument("--os", default="ubuntu-22.04")
    v.add_argument("--backend", default="docker", choices=["docker"])
    v.add_argument("--keep", action="store_true", help="keep the container for debugging")
    v.add_argument("--jobs", type=int, default=min(4, os.cpu_count() or 1),
                   help="parallel containers when verifying --all")
    v.add_argument("--no-cache", action="store_true", dest="no_cache",
                   help="ignore and do not write the verification cache")
    v.add_argument("--clear-cache", action="store_true", dest="clear_cache",
                   help="clear the verification cache before running")
    v.set_defaults(func=cmd_verify)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, FileNotFoundError, yaml.YAMLError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
