"""Human-looking account name generation.

Recipes can ask for a ``username`` parameter instead of a fixed ``choice``.
The generator draws from small first/last/role wordlists, supports several
styles, avoids system accounts, and keeps names unique within a machine.
"""

from __future__ import annotations

import random

FIRST_NAMES = (
    "james", "mary", "robert", "patricia", "john", "jennifer", "michael",
    "linda", "david", "elizabeth", "william", "barbara", "richard", "susan",
    "joseph", "jessica", "thomas", "sarah", "charles", "karen", "christopher",
    "nancy", "daniel", "lisa", "matthew", "betty", "anthony", "margaret",
    "mark", "sandra", "donald", "ashley", "steven", "kimberly", "paul",
    "emily", "andrew", "donna", "joshua", "michelle",
)

LAST_NAMES = (
    "smith", "johnson", "williams", "brown", "jones", "garcia", "miller",
    "davis", "rodriguez", "martinez", "hernandez", "lopez", "gonzalez",
    "wilson", "anderson", "thomas", "taylor", "moore", "jackson", "martin",
    "lee", "perez", "thompson", "white", "harris", "sanchez", "clark",
    "ramirez", "lewis", "robinson", "walker", "young", "allen", "king",
    "wright", "scott", "torres", "nguyen", "hill", "flores",
)

ROLES = (
    "backup", "deploy", "webadmin", "devops", "support", "finance", "ops",
    "build", "release", "monitor", "report", "staging",
)

STYLES = ("first", "last", "flast", "firstl", "first_last", "role", "svc_role")
DEFAULT_STYLES = ("first", "last", "flast", "firstl", "first_last")

RESERVED = {
    "root", "ubuntu", "boxes", "attacker", "admin", "administrator", "www-data",
    "nobody", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
    "news", "uucp", "proxy", "sshd", "ftp", "ftpuser", "anonymous",
    "backup", "list", "irc", "gnats",
    "systemd-network", "systemd-resolve", "messagebus", "_apt",
}


def _candidate(rng: random.Random, style: str) -> str:
    first = rng.choice(FIRST_NAMES)
    last = rng.choice(LAST_NAMES)
    role = rng.choice(ROLES)
    if style == "first":
        return first
    if style == "last":
        return last
    if style == "flast":
        return first[0] + last
    if style == "firstl":
        return first + last[0]
    if style == "first_last":
        return f"{first}_{last}"
    if style == "role":
        return role
    if style == "svc_role":
        return f"svc_{role}"
    raise ValueError(f"unknown username style {style!r}")


def generate_username(
    rng: random.Random,
    styles: list[str] | None = None,
    used: set[str] | None = None,
) -> str:
    styles = list(styles or DEFAULT_STYLES)
    used = used if used is not None else set()
    for _ in range(100):
        name = _candidate(rng, rng.choice(styles))
        if name not in RESERVED and name not in used:
            used.add(name)
            return name
    # Very small pools or many accounts: keep it deterministic and valid.
    for _ in range(100):
        base = _candidate(rng, rng.choice(styles))
        name = f"{base}{rng.randint(2, 99)}"[:32]
        if name not in RESERVED and name not in used:
            used.add(name)
            return name
    raise RuntimeError("could not generate a unique username")
