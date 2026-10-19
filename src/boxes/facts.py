"""Facts, terms and unification.

The world state is a set of ground-ish facts. A *plan variable* is written
``$name`` and is a place-holder that gets unified during planning and grounded
into a concrete value by the manifest.

Predicates are *typed*: ``SIGNATURES`` declares the arity of every predicate,
which is how the "typed context" is enforced (a recipe referencing an unknown
predicate, or the wrong number of arguments, fails validation).
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Var:
    """A plan variable, e.g. ``$u`` -> ``Var("u")``."""

    name: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"${self.name}"


@dataclass(frozen=True)
class Fact:
    pred: str
    args: tuple

    def __str__(self) -> str:
        return f"{self.pred}({', '.join(str(a) for a in self.args)})"


# --- parsing ---------------------------------------------------------------


def _split_args(s: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    quote: str | None = None
    for ch in s:
        if quote is not None:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            cur.append(ch)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip() != ""]


def _parse_arg(raw: str):
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        return raw[1:-1]
    if raw.startswith("$"):
        return Var(raw[1:].strip())
    if re.fullmatch(r"-?\d+", raw):
        return int(raw)
    return raw


def parse_fact(s: str) -> Fact:
    s = s.strip()
    if "(" not in s:
        return Fact(s, ())
    pred, rest = s.split("(", 1)
    rest = rest.strip()
    if not rest.endswith(")"):
        raise ValueError(f"malformed fact: {s!r}")
    inner = rest[:-1].strip()
    args = tuple(_parse_arg(a) for a in _split_args(inner))
    return Fact(pred.strip(), args)


# --- unification -----------------------------------------------------------


def _walk(t, s: dict):
    seen: set[str] = set()
    while isinstance(t, Var) and t.name in s and t.name not in seen:
        seen.add(t.name)
        t = s[t.name]
    return t


def unify(a, b, s: dict):
    a = _walk(a, s)
    b = _walk(b, s)
    if isinstance(a, Var):
        if isinstance(b, Var) and a.name == b.name:
            return s
        ns = dict(s)
        ns[a.name] = b
        return ns
    if isinstance(b, Var):
        ns = dict(s)
        ns[b.name] = a
        return ns
    if a == b:
        return s
    return None


def unify_fact(p: Fact, q: Fact, s: dict):
    if p.pred != q.pred or len(p.args) != len(q.args):
        return None
    for x, y in zip(p.args, q.args):
        s = unify(x, y, s)
        if s is None:
            return None
    return s


def subst_fact(f: Fact, s: dict) -> Fact:
    return Fact(f.pred, tuple(_walk(a, s) for a in f.args))


def rename_fact(f: Fact, prefix: str) -> Fact:
    """Give a recipe application its own variable namespace."""
    return Fact(
        f.pred,
        tuple(Var(f"{prefix}.{a.name}") if isinstance(a, Var) else a for a in f.args),
    )


def vars_in(f: Fact) -> set[str]:
    return {a.name for a in f.args if isinstance(a, Var)}


# --- typed context / predicate signatures ----------------------------------

SIGNATURES: dict[str, tuple[str, ...]] = {
    "os": ("name",),
    "host": ("name",),
    "open_port": ("host", "port"),
    "service_access": ("service", "user", "secret"),
    # Username+password pair. Dotted subtypes describe other credential shapes:
    # creds.uname, creds.pass, and later creds.auth_header, creds.cookies,
    # creds.ntlmv1, ...
    "creds": ("user", "password"),
    "creds.uname": ("user",),
    "creds.pass": ("password",),
    "knows": ("what", "value"),
    "access_shell": ("user",),
    "user_shell": ("user",),
    "access_root": (),
}

# Predicates whose trailing arguments are optional (e.g. service_access(ftp),
# service_access(ftp, user), service_access(ftp, user, secret)).
MIN_ARITY: dict[str, int] = {
    "service_access": 1,
}


def validate_fact(f: Fact) -> None:
    if f.pred not in SIGNATURES:
        raise ValueError(f"unknown predicate {f.pred!r} in {f}")
    names = SIGNATURES[f.pred]
    low = MIN_ARITY.get(f.pred, len(names))
    if not (low <= len(f.args) <= len(names)):
        if low == len(names):
            expect = f"{len(names)} argument(s)"
        else:
            expect = f"{low}..{len(names)} argument(s)"
        raise ValueError(
            f"predicate {f.pred!r} expects {expect} "
            f"({', '.join(names)}), got {len(f.args)} in {f}"
        )
