"""Docker backend: the P1 fast path.

Each machine is a container created with ``--network none`` (loopback only),
resource limits, and a long-lived ``sleep infinity`` PID 1. Recipes are
provisioned by piping scripts into ``docker exec ... sh -s``.
"""

from __future__ import annotations

import subprocess
from typing import Mapping

from .base import ExecResult


class DockerBackend:
    name = "docker"
    fidelity = "container"

    def __init__(self, binary: str = "docker") -> None:
        self.binary = binary

    # -- helpers -----------------------------------------------------------

    def _run(self, args: list[str], *, input: str | None = None, timeout: int = 120) -> ExecResult:
        try:
            proc = subprocess.run(
                [self.binary, *args],
                input=input,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            return ExecResult(127, "", f"{self.binary}: not found")
        except subprocess.TimeoutExpired:
            return ExecResult(124, "", f"timed out after {timeout}s")
        except OSError as e:
            return ExecResult(126, "", f"{self.binary}: {e}")
        return ExecResult(proc.returncode, proc.stdout, proc.stderr)

    # -- Backend protocol --------------------------------------------------

    def available(self) -> bool:
        return self._run(["info", "--format", "{{.ServerVersion}}"], timeout=15).ok

    def image_exists(self, tag: str) -> bool:
        return self._run(["image", "inspect", tag], timeout=30).ok

    def image_id(self, tag: str) -> str:
        res = self._run(["image", "inspect", "--format", "{{.Id}}", tag], timeout=30)
        return res.stdout.strip() if res.ok else tag

    def build_image(self, tag: str, context: str) -> ExecResult:
        return self._run(["build", "-t", tag, context], timeout=900)

    def network_create(self, name: str) -> ExecResult:
        # --internal: containers can reach each other, but have no route to the
        # host or the internet.
        return self._run(["network", "create", "--internal", name], timeout=60)

    def network_destroy(self, name: str) -> ExecResult:
        return self._run(["network", "rm", name], timeout=60)

    def create(
        self,
        name: str,
        image: str,
        network: str = "none",
        alias: str | None = None,
    ) -> ExecResult:
        args = [
            "run",
            "-d",
            "--name",
            name,
            "--hostname",
            alias or name,
            "--network",
            network,
        ]
        if alias:
            args += ["--network-alias", alias]
        args += [
            "--memory",
            "1g",
            "--cpus",
            "1",
            "--pids-limit",
            "256",
            image,
            "sleep",
            "infinity",
        ]
        return self._run(args, timeout=180)

    def exec(
        self,
        name: str,
        script: str,
        user: str | None = None,
        env: Mapping[str, str] | None = None,
        workdir: str | None = None,
        timeout: int = 120,
    ) -> ExecResult:
        args = ["exec", "-i"]
        if user:
            args += ["-u", user]
        if workdir:
            args += ["-w", workdir]
        for key, value in (env or {}).items():
            args += ["-e", f"{key}={value}"]
        args += [name, "sh", "-s"]
        return self._run(args, input=script, timeout=timeout)

    def put(self, name: str, src: str, dst: str) -> ExecResult:
        return self._run(["cp", src, f"{name}:{dst}"], timeout=120)

    def destroy(self, name: str) -> ExecResult:
        return self._run(["rm", "-f", name], timeout=60)
