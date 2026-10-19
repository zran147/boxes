"""Recipe model and loading."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from .difficulty import normalize as normalize_difficulty
from .facts import Fact, parse_fact, validate_fact, vars_in
from .names import STYLES as USERNAME_STYLES

KINDS = {"discovery", "service-access", "creds", "foothold", "privesc"}
GOALS = {"user", "root"}
PARAM_TYPES = {"choice", "password", "token", "int", "bool", "username"}

_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def _confined(base_dir: Path, value: object, what: str) -> Path:
    """Resolve a recipe path and require it to stay inside the recipe dir.

    Registry recipes are untrusted. Absolute paths and ``..`` must not let a
    bundle read host files or write outside its install directory.
    """
    rel = Path(str(value))
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError(f"{what} must be a relative path inside the recipe: {value!r}")
    root = base_dir.resolve()
    target = (base_dir / rel).resolve()
    try:
        target.relative_to(root)
    except ValueError as e:
        raise ValueError(f"{what} escapes the recipe directory: {value!r}") from e
    return target


@dataclass
class ParamSpec:
    name: str
    type: str
    values: list | None = None
    length: int = 16
    min: int | None = None
    max: int | None = None
    step: int = 1
    weights: list[float] | None = None
    styles: list[str] | None = None


@dataclass
class Recipe:
    id: str
    version: str
    kind: str
    os: list[str]
    difficulty: int
    requires: list[Fact]
    provides: list[Fact]
    yields: list[str]
    params: dict[str, ParamSpec]
    walkthrough: str
    description: str = ""
    # --- build/verify metadata --------------------------------------------
    # Exactly one PoC per recipe. The key ("container" or "vm") is where the
    # PoC is verified; a container PoC is assumed portable to the VM product.
    provision: str | None = None  # script, run as root inside the target
    poc: str | None = None  # the single PoC script
    poc_backend: str | None = None  # "container" | "vm"
    actor: str | None = None  # "$var" resolved from context, default "attacker"
    poc_context: str = "target"  # "target" | "attacker" (run from the attacker box)
    poc_timeout: int = 120
    assets: str | None = None  # directory copied to /opt/boxes/<id>/ in the target
    tools: list[str] | None = None  # attacker-side commands the recipe needs
    path: Path | None = None

    def __post_init__(self) -> None:
        self.difficulty = normalize_difficulty(self.difficulty)
        if not isinstance(self.id, str) or not _ID.fullmatch(self.id):
            raise ValueError(f"recipe id must match {_ID.pattern!r}, got {self.id!r}")

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

    def supports(self, fidelity: str) -> bool:
        """Where this recipe may be verified.

        A container PoC is a fast proxy and is accepted on the VM too (the same
        script runs on the product). A VM PoC can only run on a VM.
        """
        if self.poc_backend == "container":
            return fidelity in ("container", "vm")
        return self.poc_backend == fidelity

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
    if not isinstance(rid, str) or not _ID.fullmatch(rid):
        raise ValueError(f"recipe id must match {_ID.pattern!r}, got {rid!r}")
    version = str(data.get("version", ""))
    if not _SEMVER.match(version):
        raise ValueError(f"{rid}: version must be semver (x.y.z), got {version!r}")

    kind = data.get("kind")
    if kind not in KINDS:
        raise ValueError(f"{rid}: kind must be one of {sorted(KINDS)}, got {kind!r}")

    os_list = data.get("os")
    if not os_list or not isinstance(os_list, list):
        raise ValueError(f"{rid}: os must be a non-empty list")

    for key in ("requires", "provides"):
        raw = data.get(key, [])
        if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
            raise ValueError(f"{rid}: {key} must be a list of fact strings")
    requires = [parse_fact(f) for f in data.get("requires", [])]
    provides = [parse_fact(f) for f in data.get("provides", [])]
    if not requires:
        raise ValueError(f"{rid}: must declare at least one requires fact")

    yields = data.get("yields", []) or []
    if not isinstance(yields, list) or any(not isinstance(y, str) for y in yields):
        raise ValueError(f"{rid}: yields must be a list of strings")
    for y in yields:
        if y not in GOALS:
            raise ValueError(f"{rid}: yields entries must be in {sorted(GOALS)}, got {y!r}")

    for f in [*requires, *provides]:
        validate_fact(f)

    params_data = data.get("params") or {}
    if not isinstance(params_data, dict):
        raise ValueError(f"{rid}: params must be a mapping")
    params: dict[str, ParamSpec] = {}
    for name, spec in params_data.items():
        if not isinstance(name, str) or not name:
            raise ValueError(f"{rid}: param names must be non-empty strings")
        if not isinstance(spec, dict):
            raise ValueError(f"{rid}: param {name!r} must be a mapping")
        ptype = spec.get("type")
        if ptype not in PARAM_TYPES:
            raise ValueError(f"{rid}: param {name!r} type must be one of {sorted(PARAM_TYPES)}")
        values = spec.get("values")
        weights = spec.get("weights")
        styles = spec.get("styles")
        pmin = spec.get("min")
        pmax = spec.get("max")
        pstep = spec.get("step", 1)
        length = int(spec.get("length", 16))

        if ptype == "choice":
            if not values or not isinstance(values, list):
                raise ValueError(f"{rid}: choice param {name!r} needs a non-empty values list")
            if any(isinstance(v, (dict, list)) for v in values):
                raise ValueError(f"{rid}: choice param {name!r} values must be scalars")
            if weights is not None:
                if not isinstance(weights, list) or len(weights) != len(values):
                    raise ValueError(
                        f"{rid}: choice param {name!r} weights must match values"
                    )
                if any(float(w) <= 0 for w in weights):
                    raise ValueError(f"{rid}: choice param {name!r} weights must be positive")
        elif ptype == "int":
            if not isinstance(pmin, int) or not isinstance(pmax, int):
                raise ValueError(f"{rid}: int param {name!r} needs integer min and max")
            if pmin > pmax:
                raise ValueError(f"{rid}: int param {name!r} min must be <= max")
            if not isinstance(pstep, int) or pstep <= 0:
                raise ValueError(f"{rid}: int param {name!r} step must be a positive integer")
        elif ptype == "username":
            if styles is not None:
                if not isinstance(styles, list) or not styles:
                    raise ValueError(f"{rid}: username param {name!r} styles must be a non-empty list")
                for style in styles:
                    if style not in USERNAME_STYLES:
                        raise ValueError(
                            f"{rid}: username param {name!r} has unknown style {style!r}"
                        )
        elif ptype in {"password", "token"}:
            if length <= 0:
                raise ValueError(f"{rid}: {ptype} param {name!r} length must be positive")
        else:  # bool
            pass

        params[name] = ParamSpec(
            name=name,
            type=ptype,
            values=values if ptype == "choice" else None,
            length=length,
            min=pmin if ptype == "int" else None,
            max=pmax if ptype == "int" else None,
            step=pstep if ptype == "int" else 1,
            weights=[float(w) for w in weights] if ptype == "choice" and weights else None,
            styles=styles if ptype == "username" else None,
        )

    base_dir = path.parent
    if "fidelity" in data:
        raise ValueError(
            f"{rid}: fidelity is no longer supported; use poc.container or poc.vm"
        )
    provision = data.get("provision")
    poc_data = data.get("poc")
    poc: str | None = None
    poc_backend: str | None = None
    poc_context = "target"
    if isinstance(poc_data, dict):
        poc_context = str(poc_data.get("context", "target"))
        present = [key for key in ("container", "vm") if key in poc_data]
        if len(present) != 1:
            raise ValueError(
                f"{rid}: poc must contain exactly one of 'container' or 'vm'"
            )
        poc_backend = present[0]
        poc = str(poc_data[poc_backend])
    elif poc_data is not None:
        raise ValueError(
            f"{rid}: poc must be a mapping with context and exactly one of container/vm"
        )
    if poc_context not in {"target", "attacker"}:
        raise ValueError(f"{rid}: poc.context must be 'target' or 'attacker', got {poc_context!r}")

    if (poc is None) != (provision is None):
        raise ValueError(f"{rid}: provision and poc must be provided together")
    if poc is not None and not _confined(base_dir, poc, f"{rid}: poc").is_file():
        raise ValueError(f"{rid}: poc script not found: {base_dir / poc}")
    if provision is not None and not _confined(
        base_dir, provision, f"{rid}: provision"
    ).is_file():
        raise ValueError(f"{rid}: provision script not found: {base_dir / str(provision)}")
    poc_timeout = int(data.get("poc_timeout", 120))
    if poc_timeout <= 0:
        raise ValueError(f"{rid}: poc_timeout must be positive, got {poc_timeout}")

    actor = str(data["actor"]) if data.get("actor") is not None else None
    if actor is not None and not actor.strip():
        raise ValueError(f"{rid}: actor must not be empty")

    tools = data.get("tools") or []
    if not isinstance(tools, list) or any(not isinstance(t, str) or not t for t in tools):
        raise ValueError(f"{rid}: tools must be a list of non-empty strings")
    assets = data.get("assets")
    if assets is None and (base_dir / "files").is_dir():
        assets = "./files"
    if assets is not None and not _confined(
        base_dir, assets, f"{rid}: assets"
    ).is_dir():
        raise ValueError(f"{rid}: assets directory not found: {base_dir / str(assets)}")

    return Recipe(
        id=rid,
        version=version,
        kind=kind,
        os=[str(p) for p in os_list],
        difficulty=data.get("difficulty", 5),
        requires=requires,
        provides=provides,
        yields=list(yields),
        params=params,
        walkthrough=str(data.get("walkthrough", "")).strip(),
        description=str(data.get("description", "")).strip(),
        provision=str(provision) if provision else None,
        poc=str(poc) if poc else None,
        poc_backend=poc_backend,
        actor=actor,
        poc_context=poc_context,
        poc_timeout=poc_timeout,
        assets=str(assets) if assets else None,
        tools=[str(t) for t in tools],
        path=path,
    )
