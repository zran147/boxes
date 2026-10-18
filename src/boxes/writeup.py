"""Render a plan + manifest into a human-readable walkthrough."""

from __future__ import annotations

import re

from .manifest import Manifest
from .planner import Plan

_PLACEHOLDER = re.compile(r"\{([A-Za-z0-9_.]+)\}")


def _render(template: str, ctx: dict) -> str:
    def sub(m: re.Match) -> str:
        key = m.group(1)
        return str(ctx[key]) if key in ctx else m.group(0)

    return _PLACEHOLDER.sub(sub, template)


def _steps_markdown(plan: Plan, manifest: Manifest, start: int = 0, end: int | None = None) -> list[str]:
    lines: list[str] = []
    last = len(plan.steps) if end is None else end
    for idx in range(start, last):
        step = plan.steps[idx]
        r = step.recipe
        i = idx + 1
        if idx == plan.user_index:
            tag = "  → **user flag**"
        elif idx == plan.root_index:
            tag = "  → **root flag**"
        else:
            tag = ""
        lines.append(f"### Step {i} — `{r.id}` ({r.kind}){tag}")
        lines.append(f"`v{r.version}` · difficulty `{r.difficulty}`")
        lines.append("")
        if r.description:
            lines.append(r.description)
            lines.append("")
        body = _render(r.walkthrough, manifest.step_context(step)).strip()
        if body:
            lines.append(body)
            lines.append("")
    return lines


def render_markdown(plan: Plan, manifest: Manifest) -> str:
    lines: list[str] = []
    lines.append(f"# Generated machine — {plan.os_name}")
    lines.append("")
    lines.append(f"- plan seed: `{plan.seed}`")
    lines.append(f"- build seed: `{manifest.build_seed}`")
    lines.append(f"- services: {', '.join(str(p) for p in plan.ports)}")
    lines.append(f"- steps to user flag: {plan.user_index + 1}")
    lines.append(f"- steps to root flag: {plan.root_index - plan.user_index}")
    lines.append("")
    lines.extend(_steps_markdown(plan, manifest))
    return "\n".join(lines).rstrip() + "\n"


def _common_prefix(paths: list[Plan]) -> int:
    length = 0
    while all(len(path.steps) > length for path in paths):
        if len({path.steps[length].instance for path in paths}) != 1:
            break
        length += 1
    return length


def render_machine_markdown(paths: list[Plan], manifests: list[Manifest]) -> str:
    first = paths[0]
    prefix = _common_prefix(paths)
    lines: list[str] = []
    lines.append(f"# Generated machine — {first.os_name}")
    lines.append("")
    lines.append(f"- base plan seed: `{first.seed}`")
    lines.append(f"- build seed: `{manifests[0].build_seed}`")
    lines.append(f"- paths: {len(paths)} (experimental)")
    if prefix:
        lines.append(f"- shared prefix: {prefix} step(s)")
    lines.append("")
    if prefix:
        lines.append(f"## Shared prefix ({prefix} step(s))")
        lines.append("")
        lines.extend(_steps_markdown(first, manifests[0], 0, prefix))
    for index, (plan, manifest) in enumerate(zip(paths, manifests), 1):
        lines.append(f"## Path {index}" + (" branch" if prefix else ""))
        lines.append(f"plan seed `{plan.seed}` · services {', '.join(str(p) for p in plan.ports)}")
        lines.append("")
        lines.extend(_steps_markdown(plan, manifest, prefix))
    return "\n".join(lines).rstrip() + "\n"


def plan_to_dict(plan: Plan, manifest: Manifest) -> dict:
    steps = []
    for i, step in enumerate(plan.steps, 1):
        r = step.recipe
        steps.append(
            {
                "index": i,
                "instance": step.instance,
                "recipe": r.id,
                "version": r.version,
                "kind": r.kind,
                "difficulty": r.difficulty,
                "yields": r.yields,
                "requires": [str(manifest.ground_fact(f)) for f in step.requires],
                "provides": [str(manifest.ground_fact(f)) for f in step.provides],
                "context": manifest.step_context(step),
                "walkthrough": _render(r.walkthrough, manifest.step_context(step)).strip(),
            }
        )
    return {
        "os": plan.os_name,
        "plan_seed": plan.seed,
        "build_seed": manifest.build_seed,
        "services": plan.ports,
        "steps_to_user": plan.user_index + 1,
        "steps_to_root": plan.root_index - plan.user_index,
        "steps": steps,
        "manifest": {k: v for k, v in manifest.values.items()},
    }


def paths_to_dict(paths: list[Plan], manifests: list[Manifest]) -> dict:
    return {
        "os": paths[0].os_name,
        "base_plan_seed": paths[0].seed,
        "build_seed": manifests[0].build_seed,
        "shared_prefix": _common_prefix(paths),
        "paths": [plan_to_dict(plan, manifest) for plan, manifest in zip(paths, manifests)],
    }
