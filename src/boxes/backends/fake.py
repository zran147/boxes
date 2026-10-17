"""In-memory backend for unit tests.

It records every call and can be given a responder to simulate failures.
It does not try to emulate a real machine.
"""

from __future__ import annotations

from typing import Callable, Mapping

from .base import ExecResult

Responder = Callable[[str, str, str | None, Mapping[str, str]], ExecResult]


class FakeBackend:
    name = "fake"
    fidelity = "container"

    def __init__(
        self,
        responder: Responder | None = None,
        images: set[str] | None = None,
    ) -> None:
        self.responder = responder or (lambda *_: ExecResult(0, "ok", ""))
        self.images = set(images or [])
        self.calls: list[tuple] = []
        self.created: list[str] = []
        self.destroyed: list[str] = []

    def available(self) -> bool:
        return True

    def image_exists(self, tag: str) -> bool:
        return tag in self.images

    def image_id(self, tag: str) -> str:
        return f"fake-id:{tag}"

    def pid(self, name: str) -> int:
        return 12345

    def build_image(self, tag: str, context: str) -> ExecResult:
        self.calls.append(("build_image", tag, context))
        self.images.add(tag)
        return ExecResult(0, "", "")

    def network_create(self, name: str, attacker_pid: int | None = None) -> ExecResult:
        self.calls.append(("network_create", name, attacker_pid))
        return ExecResult(0, "", "")

    def network_destroy(self, name: str) -> ExecResult:
        self.calls.append(("network_destroy", name))
        return ExecResult(0, "", "")

    def create(
        self,
        name: str,
        image: str,
        network: str = "none",
        alias: str | None = None,
        provision: bool = False,
    ) -> ExecResult:
        self.calls.append(("create", name, image, network, alias, provision))
        self.created.append(name)
        return ExecResult(0, "", "")

    def exec(
        self,
        name: str,
        script: str,
        user: str | None = None,
        env: Mapping[str, str] | None = None,
        workdir: str | None = None,
        timeout: int = 120,
    ) -> ExecResult:
        self.calls.append(("exec", name, script, user, dict(env or {}), timeout))
        return self.responder(name, script, user, dict(env or {}))

    def put(self, name: str, src: str, dst: str) -> ExecResult:
        self.calls.append(("put", name, src, dst))
        return ExecResult(0, "", "")

    def seal(self, name: str) -> ExecResult:
        self.calls.append(("seal", name))
        return ExecResult(0, "", "")

    def destroy(self, name: str) -> ExecResult:
        self.calls.append(("destroy", name))
        self.destroyed.append(name)
        return ExecResult(0, "", "")
