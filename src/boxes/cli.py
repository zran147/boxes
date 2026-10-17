"""Command line interface."""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

import yaml

from .harness import check_recipe
from .lint import lint
from .manifest import materialize
from .planner import generate, satisfies
from .registry import load_registry, select
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

    rng = random.Random(seed ^ 0xB0_5E5)
    manifest = materialize(plan, rng)

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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="boxes", description="HTB-style machine generator (P0)")
    p.add_argument("--recipes", default=str(DEFAULT_RECIPES), help="recipe directory")
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("gen", help="generate a machine plan")
    g.add_argument("--os", default="ubuntu-22.04")
    g.add_argument("--to-user", type=int, default=3, dest="to_user")
    g.add_argument("--to-root", type=int, default=2, dest="to_root")
    g.add_argument("--seed", type=int, default=None)
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

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, FileNotFoundError, yaml.YAMLError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
