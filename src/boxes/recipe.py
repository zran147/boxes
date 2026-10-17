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
    # --- build/verify metadata --------------------------------------------
    # A recipe can provide separate PoCs for the container proxy and the VM
    # product. `fidelity`/`poc` are the legacy single-backend form.
    fidelity: str | None = None
    provision: str | None = None  # script, run as root inside the target
    poc: str | None = None  # legacy single PoC
    poc_scripts: dict[str, str] = field(default_factory=dict)  # backend -> script
    actor: str | None = None  # "$var" resolved from context, default "attacker"
    poc_context: str = "target"  # "target" | "attacker" (run from the attacker box)
    poc_timeout: int = 120
    assets: str | None = None  # directory copied to /opt/boxes/<id>/ in the target
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
    def assets_dir(self) -> Path | None:
        return self.dir / self.assets if self.assets else None

    @property
    def fidelities(self) -> list[str]:
        if self.poc_scripts:
            return sorted(self.poc_scripts)
        if self.fidelity:
            return [self.fidelity]
        return ["container"]

    def supports(self, fidelity: str) -> bool:
        if self.poc_scripts:
            return fidelity in self.poc_scripts
        if self.fidelity:
            return self.fidelity == fidelity
        return fidelity == "container"

    def poc_script(self, fidelity: str) -> str | None:
        if self.poc_scripts:
            return self.poc_scripts.get(fidelity)
        if self.fidelity is None or self.fidelity == fidelity:
            return self.poc
        return None

    @property
    def verifiable(self) -> bool:
        return self.provision is not None and (bool(self.poc_scripts) or self.poc is not None)

    def script(self, kind: str, fidelity: str | None = None) -> Path:
        if kind == "provision":
            rel = self.provision
        else:
            rel = self.poc_script(fidelity or self.fidelity or "container")
        if rel is None:
            raise ValueError(f"{self.id}: no {kind} script for {fidelity!r}")
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
    fidelity = data.get("fidelity")
    if fidelity is not None:
        fidelity = str(fidelity)
        if fidelity not in {"container", "vm"}:
            raise ValueError(f"{rid}: fidelity must be 'container' or 'vm', got {fidelity!r}")
    provision = data.get("provision")
    poc_data = data.get("poc")
    poc: str | None = None
    poc_scripts: dict[str, str] = {}
    poc_context = "target"
    if isinstance(poc_data, str):
        poc = poc_data
    elif isinstance(poc_data, dict):
        poc_context = str(poc_data.get("context", "target"))
        if "script" in poc_data:
            poc = str(poc_data["script"])
        for backend in ("container", "vm"):
            if backend in poc_data:
                poc_scripts[backend] = str(poc_data[backend])
    elif poc_data is not None:
        raise ValueError(f"{rid}: poc must be a path or a mapping with script/context or container/vm")

    if not poc_scripts and poc is not None:
        # legacy form: a single PoC, placed on the declared fidelity (or container)
        poc_scripts[fidelity if fidelity in ("container", "vm") else "container"] = poc
    if poc_context not in {"target", "attacker"}:
        raise ValueError(f"{rid}: poc.context must be 'target' or 'attacker', got {poc_context!r}")

    for backend, rel in poc_scripts.items():
        if not (base_dir / rel).is_file():
            raise ValueError(f"{rid}: poc.{backend} script not found: {base_dir / rel}")
    if provision is not None and not (base_dir / str(provision)).is_file():
        raise ValueError(f"{rid}: provision script not found: {base_dir / str(provision)}")
    if bool(poc_scripts) != (provision is not None):
        raise ValueError(f"{rid}: provision and at least one poc script must be provided together")
    poc_timeout = int(data.get("poc_timeout", 120))
    if poc_timeout <= 0:
        raise ValueError(f"{rid}: poc_timeout must be positive, got {poc_timeout}")

    assets = data.get("assets")
    if assets is None and (base_dir / "files").is_dir():
        assets = "./files"
    if assets is not None and not (base_dir / str(assets)).is_dir():
        raise ValueError(f"{rid}: assets directory not found: {base_dir / str(assets)}")

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
        poc_scripts=poc_scripts,
        actor=str(data["actor"]) if data.get("actor") is not None else None,
        poc_context=poc_context,
        poc_timeout=poc_timeout,
        assets=str(assets) if assets else None,
        path=path,
    )
