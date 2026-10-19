"""Docker backend: the P1 fast path.

Each machine is a container created with ``--network none`` (loopback only),
resource limits, and a long-lived ``sleep infinity`` PID 1. Recipes are
provisioned by piping scripts into ``docker exec ... sh -s``.
"""

from __future__ import annotations

import subprocess
from typing import Mapping

from .base import ExecResult

# Minimal capabilities for a target that must create users, start sshd/vsftpd,
# bind low ports, and simulate setuid/sudo privesc inside the container.
TARGET_CAPS = (
    "AUDIT_WRITE",
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "NET_BIND_SERVICE",
    "SETFCAP",
    "SETGID",
    "SETPCAP",
    "SETUID",
    "SYS_CHROOT",
)
# The attacker needs no privileged capabilities; NET_RAW keeps nmap usable.
ATTACKER_CAPS = ("NET_RAW",)


class DockerBackend:
    name = "docker"
    fidelity = "container"

    def __init__(self, binary: str = "docker", sandbox: str = "trusted") -> None:
        self.binary = binary
        self.sandbox = sandbox

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

    def pid(self, name: str) -> int:
        res = self._run(["inspect", "-f", "{{.State.Pid}}", name], timeout=30)
        try:
            return int(res.stdout.strip())
        except ValueError:
            return 0

    def build_image(self, tag: str, context: str) -> ExecResult:
        return self._run(["build", "-t", tag, context], timeout=900)

    def network_create(self, name: str, attacker_pid: int | None = None) -> ExecResult:
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
        provision: bool = False,
    ) -> ExecResult:
        args = [
            "run",
            "-d",
            "--name",
            name,
            "--hostname",
            alias or "sandbox",
            "--network",
            network,
        ]
        if alias:
            args += ["--network-alias", alias]
        if self.sandbox == "locked":
            attacker = name.startswith("boxes-attacker")
            caps = ATTACKER_CAPS if attacker else TARGET_CAPS
            args += ["--cap-drop", "ALL"]
            for cap in caps:
                args += ["--cap-add", cap]
            args += ["--ulimit", "nofile=4096:4096"]
            if attacker:
                # The target must keep setuid semantics for sudo/SUID recipes.
                args += ["--security-opt", "no-new-privileges"]
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
        res = self._run(args, timeout=180)
        if res.ok and provision:
            net = self._run(["network", "connect", "boxes-provision", name], timeout=60)
            if not net.ok:
                self.destroy(name)
                return net
        return res

    def seal(self, name: str) -> ExecResult:
        """Disconnect the provisioning network before PoCs."""
        return self._run(["network", "disconnect", "-f", "boxes-provision", name], timeout=60)

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
