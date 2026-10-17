"""`boxes new`: scaffold a recipe that already passes lint and the harness."""

from __future__ import annotations

import re
from pathlib import Path

_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")

_TEMPLATES: dict[str, str] = {
    "discovery": """\
id: {rid}
version: 0.1.0
kind: discovery
description: "TODO: what this discovery step uncovers."
os: [{os}]
difficulty: {difficulty}
requires:
  - net.port($h, 80)
provides:
  - knows(path, $value)
params:
  value:
    type: choice
    values: ["/admin.php", "/backup.zip"]
walkthrough: |
  TODO: describe how `{{value}}` is discovered. Discovery produces knowledge
  only -- it must not grant access or credentials.
""",
    "service-access": """\
id: {rid}
version: 0.1.0
kind: service-access
description: "TODO: how access to the service is obtained."
os: [{os}]
difficulty: {difficulty}
requires:
  - net.port($h, 21)
provides:
  - service_access($service)
params:
  service:
    type: choice
    values: ["ftp"]
walkthrough: |
  TODO: describe how `{{service}}` access is gained (default creds, anonymous,
  etc.).
""",
    "creds": """\
id: {rid}
version: 0.1.0
kind: creds
description: "TODO: where the credentials are found."
os: [{os}]
difficulty: {difficulty}
requires:
  - net.port($h, 80)
provides:
  - creds($user, $pass)
  - creds($user)
  - creds($pass)
params:
  user:
    type: choice
    values: ["deploy", "backup"]
  pass:
    type: password
    length: 14
walkthrough: |
  TODO: describe where `{{user}}` / `{{pass}}` leak from.
""",
    "foothold": """\
id: {rid}
version: 0.1.0
kind: foothold
description: "TODO: how an interactive shell is obtained."
os: [{os}]
difficulty: {difficulty}
yields: ["user"]
requires:
  - net.port($h, 22)
provides:
  - access_shell($user)
params:
  user:
    type: choice
    values: ["www-data"]
walkthrough: |
  TODO: describe how `{{user}}` gets a shell. If that principal owns
  user.txt, note that the user flag is read here.
""",
    "privesc": """\
id: {rid}
version: 0.1.0
kind: privesc
description: "TODO: the privilege-escalation primitive."
os: [{os}]
difficulty: {difficulty}
yields: ["root"]
requires:
  - access_shell($u)
provides:
  - access_root()
params:
  binary:
    type: choice
    values: ["/usr/bin/find", "/usr/bin/vim"]
walkthrough: |
  TODO: describe how `{{u}}` abuses `{{binary}}` to become root and read
  root.txt.
""",
}


def create_recipe(
    root: str | Path,
    rid: str,
    kind: str,
    os_patterns: list[str] | None = None,
    difficulty: float = 0.3,
) -> Path:
    if not _ID.match(rid):
        raise ValueError(f"recipe id must match {_ID.pattern!r}, got {rid!r}")
    if kind not in _TEMPLATES:
        raise ValueError(f"kind must be one of {sorted(_TEMPLATES)}, got {kind!r}")

    root = Path(root)
    target = root / rid
    if target.exists():
        raise FileExistsError(f"recipe already exists: {target}")

    os_patterns = os_patterns or ["ubuntu-*"]
    text = _TEMPLATES[kind].format(
        rid=rid,
        kind=kind,
        os=", ".join(f'"{p}"' for p in os_patterns),
        difficulty=difficulty,
    )
    target.mkdir(parents=True)
    path = target / "recipe.yaml"
    path.write_text(text)
    return path
