"""Command line interface."""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

import yaml

from .backends import get_backend
from .harness import check_recipe
from .images import ensure_image, image_tag
from .lint import lint
from .manifest import materialize
from .planner import generate, satisfies
from .registry import load_registry, select
from .runner import verify_machine, verify_recipe
from .scaffold import create_recipe
from .writeup import plan_to_dict, render_markdown

DEFAULT_RECIPES = Path("recipes")


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

    build_seed = args.build_seed if args.build_seed is not None else seed
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


def _prepare_backend(args):
    backend = get_backend(args.backend)
    if not backend.available():
        print(f"backend {args.backend!r} is not available", file=sys.stderr)
        return None
    res = ensure_image(backend, args.os, getattr(args, "rebuild", False))
    if not res.ok:
        print(f"base image {image_tag(args.os)} is not ready:", file=sys.stderr)
        print(res.output(), file=sys.stderr)
        return None
    return backend


def cmd_image(args) -> int:
    backend = _prepare_backend(args)
    if backend is None:
        return 2
    print(f"base image ready: {image_tag(args.os)}")
    return 0


def cmd_verify(args) -> int:
    backend = _prepare_backend(args)
    if backend is None:
        return 2

    if args.machine:
        recipes = load_registry(args.recipes)
        pool = select(recipes, args.os)
        plan = generate(pool, args.os, args.to_user, args.to_root, args.seed)
        if plan is None:
            print("could not generate a machine for those depths", file=sys.stderr)
            return 1
        build_seed = args.build_seed if args.build_seed is not None else args.seed
        manifest = materialize(plan, build_seed)
        print("chain: " + " -> ".join(s.recipe.id for s in plan.steps))
        result = verify_machine(plan, manifest, backend, image_tag(args.os), keep=args.keep)
        _print_verify(result)
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

    failed = 0
    ran = 0
    for r in targets:
        if not r.verifiable:
            print(f"SKIP {r.id} (symbolic only: no provision/poc)")
            continue
        fixture = check_recipe(r, args.seed).fixture
        if fixture is None:
            print(f"FAIL {r.id}: harness produced no fixture", file=sys.stderr)
            failed += 1
            continue
        result = verify_recipe(r, fixture, backend, image_tag(args.os), keep=args.keep)
        _print_verify(result)
        ran += 1
        failed += 0 if result.ok else 1

    if ran == 0:
        print("no verifiable recipes", file=sys.stderr)
        return 1
    print(f"\n{ran - failed}/{ran} recipe(s) verified")
    return 0 if failed == 0 else 1


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
                   help="param materialisation seed (defaults to --seed)")
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
    ib.add_argument("--backend", default="docker")
    ib.set_defaults(func=cmd_image)

    v = sub.add_parser("verify", help="build and verify recipes or a machine")
    v.add_argument("--recipe", help="verify one recipe in isolation (L2)")
    v.add_argument("--all", action="store_true", help="verify every verifiable recipe")
    v.add_argument("--machine", action="store_true", help="build and verify a full chain (L3)")
    v.add_argument("--seed", type=int, default=0)
    v.add_argument("--build-seed", type=int, default=None, dest="build_seed",
                   help="param materialisation seed (defaults to --seed)")
    v.add_argument("--to-user", type=int, default=1, dest="to_user")
    v.add_argument("--to-root", type=int, default=1, dest="to_root")
    v.add_argument("--os", default="ubuntu-22.04")
    v.add_argument("--backend", default="docker")
    v.add_argument("--keep", action="store_true", help="keep the container for debugging")
    v.set_defaults(func=cmd_verify)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, FileNotFoundError, yaml.YAMLError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
