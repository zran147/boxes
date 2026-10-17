"""Backend protocol shared by Docker / Incus / QEMU."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol, runtime_checkable


@dataclass
class ExecResult:
    exit_code: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def output(self, limit: int = 2000) -> str:
        text = (self.stdout + self.stderr).strip()
        return text if len(text) <= limit else text[:limit] + "...<truncated>"


@runtime_checkable
class Backend(Protocol):
    name: str

    def available(self) -> bool: ...

    def image_exists(self, tag: str) -> bool: ...

    def image_id(self, tag: str) -> str: ...

    def build_image(self, tag: str, context: str) -> ExecResult: ...

    def network_create(self, name: str, attacker_pid: int | None = None) -> ExecResult: ...

    def network_destroy(self, name: str) -> ExecResult: ...

    def create(
        self,
        name: str,
        image: str,
        network: str = "none",
        alias: str | None = None,
    ) -> ExecResult: ...

    def exec(
        self,
        name: str,
        script: str,
        user: str | None = None,
        env: Mapping[str, str] | None = None,
        workdir: str | None = None,
        timeout: int = 120,
    ) -> ExecResult: ...

    def put(self, name: str, src: str, dst: str) -> ExecResult: ...

    def destroy(self, name: str) -> ExecResult: ...
