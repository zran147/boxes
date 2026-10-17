"""Recipe model and loading."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .facts import Fact, parse_fact, validate_fact, vars_in

KINDS = {"discovery", "service-access", "creds", "foothold", "privesc"}
GOALS = {"user", "root"}
PARAM_TYPES = {"choice", "password", "token"}

_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


@dataclass
class ParamSpec:
    name: str
    type: str
    values: list | None = None
    length: int = 16


@dataclass
class Recipe:
    id: str
    version: str
    kind: str
    os: list[str]
    difficulty: float
    requires: list[Fact]
    provides: list[Fact]
    yields: list[str]
    params: dict[str, ParamSpec]
    walkthrough: str
    description: str = ""
    # --- P1 build/verify metadata -----------------------------------------
    # "container" recipes can be realised by the fast path (Docker/Incus);
    # "vm" recipes need a real kernel and are P1-vm territory.
    fidelity: str = "container"
    provision: str | None = None  # script, run as root inside the target
    poc: str | None = None  # script, run as the actor; exit 0 = proven
    actor: str | None = None  # "$var" resolved from context, default "attacker"
    poc_timeout: int = 120
    path: Path | None = None

    def applies_to(self, os_name: str) -> bool:
        from fnmatch import fnmatch

        return any(fnmatch(os_name, pat) for pat in self.os)

    @property
    def dir(self) -> Path:
        if self.path is None:
            raise ValueError(f"recipe {self.id} has no path; cannot resolve assets")
        return self.path.parent

    @property
    def verifiable(self) -> bool:
        return self.provision is not None and self.poc is not None

    def script(self, kind: str) -> Path:
        rel = self.provision if kind == "provision" else self.poc
        if rel is None:
            raise ValueError(f"{self.id}: no {kind} script")
        return self.dir / rel

    def param_vars(self) -> set[str]:
        return set(self.params)

    def requires_vars(self) -> set[str]:
        out: set[str] = set()
        for f in self.requires:
            out |= vars_in(f)
        return out


def load_recipe(path: Path) -> Recipe:
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"{path}: recipe file must be a mapping")

    rid = data.get("id") or path.parent.name
    version = str(data.get("version", ""))
    if not _SEMVER.match(version):
        raise ValueError(f"{rid}: version must be semver (x.y.z), got {version!r}")

    kind = data.get("kind")
    if kind not in KINDS:
        raise ValueError(f"{rid}: kind must be one of {sorted(KINDS)}, got {kind!r}")

    os_list = data.get("os")
    if not os_list or not isinstance(os_list, list):
        raise ValueError(f"{rid}: os must be a non-empty list")

    requires = [parse_fact(f) for f in data.get("requires", [])]
    provides = [parse_fact(f) for f in data.get("provides", [])]
    if not requires:
        raise ValueError(f"{rid}: must declare at least one requires fact")

    yields = data.get("yields", []) or []
    for y in yields:
        if y not in GOALS:
            raise ValueError(f"{rid}: yields entries must be in {sorted(GOALS)}, got {y!r}")

    for f in [*requires, *provides]:
        validate_fact(f)

    params: dict[str, ParamSpec] = {}
    for name, spec in (data.get("params") or {}).items():
        if not isinstance(spec, dict):
            raise ValueError(f"{rid}: param {name!r} must be a mapping")
        ptype = spec.get("type")
        if ptype not in PARAM_TYPES:
            raise ValueError(f"{rid}: param {name!r} type must be one of {sorted(PARAM_TYPES)}")
        values = spec.get("values")
        if ptype == "choice" and (not values or not isinstance(values, list)):
            raise ValueError(f"{rid}: choice param {name!r} needs a non-empty values list")
        params[name] = ParamSpec(
            name=name,
            type=ptype,
            values=values,
            length=int(spec.get("length", 16)),
        )

    base_dir = path.parent
    fidelity = str(data.get("fidelity", "container"))
    if fidelity not in {"container", "vm"}:
        raise ValueError(f"{rid}: fidelity must be 'container' or 'vm', got {fidelity!r}")
    provision = data.get("provision")
    poc = data.get("poc")
    for phase, rel in (("provision", provision), ("poc", poc)):
        if rel is not None and not (base_dir / str(rel)).is_file():
            raise ValueError(f"{rid}: {phase} script not found: {base_dir / str(rel)}")
    if (provision is None) != (poc is None):
        raise ValueError(f"{rid}: provision and poc must be provided together")

    return Recipe(
        id=rid,
        version=version,
        kind=kind,
        os=[str(p) for p in os_list],
        difficulty=float(data.get("difficulty", 0.5)),
        requires=requires,
        provides=provides,
        yields=list(yields),
        params=params,
        walkthrough=str(data.get("walkthrough", "")).strip(),
        description=str(data.get("description", "")).strip(),
        fidelity=fidelity,
        provision=str(provision) if provision else None,
        poc=str(poc) if poc else None,
        actor=str(data["actor"]) if data.get("actor") is not None else None,
        poc_timeout=int(data.get("poc_timeout", 120)),
        path=path,
    )
