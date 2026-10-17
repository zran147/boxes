"""Recipe lint: cheap, static guardrails run before any planning happens."""

from __future__ import annotations

from .facts import vars_in
from .recipe import Recipe

PRELUDE_PREDS = {"open_port", "os", "host"}


def lint(recipes: list[Recipe]) -> list[str]:
    errs: list[str] = []
    for r in recipes:
        if r.yields:
            if "user" in r.yields and "root" in r.yields:
                errs.append(f"{r.id}: a single recipe may not yield both the user and root flag")

            # only a foothold reaches the user flag; only a privesc reaches root
            if "user" in r.yields and r.kind != "foothold":
                errs.append(f"{r.id}: yields the user flag but is kind {r.kind!r} (must be 'foothold')")
            if "root" in r.yields and r.kind != "privesc":
                errs.append(f"{r.id}: yields the root flag but is kind {r.kind!r} (must be 'privesc')")

            # anti-shortcut: anything other than a foothold must do real work
            # (a foothold may legitimately exploit network exposure directly,
            # e.g. an unauthenticated RCE that drops a shell in one step).
            non_trivial = [f for f in r.requires if f.pred not in PRELUDE_PREDS]
            if r.kind != "foothold" and not non_trivial:
                errs.append(
                    f"{r.id}: yields {r.yields} but only requires prelude facts "
                    f"(must require a foothold/knowledge fact first)"
                )

        bound = r.requires_vars() | set(r.params)
        for f in r.provides:
            for v in vars_in(f):
                if v not in bound:
                    errs.append(
                        f"{r.id}: provides fact uses ${v}, which is neither a param "
                        f"nor bound by a requires fact"
                    )
    return errs
