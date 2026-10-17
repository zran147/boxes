"""QEMU backend (experimental).

Design decisions driven by measurements on a TCG-only host:

* one boot per machine, dominated by boot time;
* a **persistent SSH ControlMaster** per VM: fresh execs cost ~5s under TCG,
  reused ones ~0.1s;
* a **pre-baked base image** (cloud-init already run) so subsequent boots skip
  first-boot work;
* ``savevm``/``loadvm`` on the qcow2 overlay for snapshotting a provisioned
  machine and restoring it (multi-path, per-step repro).

Networking is user-mode (``-netdev user``) with an SSH hostfwd for management,
plus an optional tap NIC for the attacker container on a shared bridge. The
management NIC is always added first so the pre-baked netplan keeps DHCP/SSH.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import time
from pathlib import Path

from .base import ExecResult

QEMU = "qemu-system-x86_64"
BOOT_TIMEOUT = 600
TAP_MAC = "52:54:00:be:ef:01"
PROV_MAC = "52:54:00:be:ef:02"


class QemuBackend:
    name = "qemu"
    fidelity = "vm"

    def __init__(
        self,
        store: Path | None = None,
        base: Path | None = None,
        key: Path | None = None,
        user: str = "boxes",
    ) -> None:
        root = Path(__file__).resolve().parents[3]
        self.store = Path(store or os.environ.get("BOXES_VM_STORE", root / ".boxes-vm"))
        self.base = Path(base or os.environ.get("BOXES_VM_BASE", self.store / "base-prebaked.qcow2"))
        self.key = Path(key or os.environ.get("BOXES_VM_KEY", self.store / "boxes_key"))
        self.seed = self.store / "seed.iso"
        self.user = user
        self.run_dir = self.store / "run"
        self.run_dir.mkdir(parents=True, exist_ok=True)

    # -- helpers -----------------------------------------------------------

    def _run(self, args: list[str], *, input: str | None = None, timeout: int = 120) -> ExecResult:
        try:
            proc = subprocess.run(args, input=input, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            return ExecResult(127, "", f"{args[0]}: not found")
        except subprocess.TimeoutExpired:
            return ExecResult(124, "", f"timed out after {timeout}s")
        except OSError as e:
            return ExecResult(126, "", str(e))
        return ExecResult(proc.returncode, proc.stdout, proc.stderr)

    def _state_path(self, name: str) -> Path:
        return self.run_dir / f"{name}.json"

    def _load(self, name: str) -> dict:
        return json.loads(self._state_path(name).read_text())

    def _save(self, name: str, state: dict) -> None:
        self._state_path(name).write_text(json.dumps(state))

    def _sock(self, name: str) -> str:
        return f"/tmp/boxes-ssh-{name}.sock"[:100]

    def _mon(self, name: str) -> Path:
        return self.run_dir / f"{name}.mon"

    def _ssh_base(self, name: str) -> list[str]:
        st = self._load(name)
        return [
            "ssh",
            "-S", self._sock(name),
            "-i", str(self.key),
            "-p", str(st["port"]),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
        ]

    def _wait_ssh(self, name: str, timeout: int = BOOT_TIMEOUT) -> bool:
        st = self._load(name)
        deadline = time.time() + timeout
        cmd = [
            "ssh", "-i", str(self.key), "-p", str(st["port"]),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=3",
            "-o", "BatchMode=yes",
            f"{self.user}@127.0.0.1", "true",
        ]
        while time.time() < deadline:
            if self._run(cmd, timeout=10).ok:
                # start the persistent master used by every subsequent exec
                Path(self._sock(name)).unlink(missing_ok=True)
                master = [
                    "ssh", "-M", "-S", self._sock(name), "-fN",
                    "-i", str(self.key), "-p", str(st["port"]),
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    f"{self.user}@127.0.0.1",
                ]
                return self._run(master, timeout=30).ok
            time.sleep(3)
        return False

    def _monitor(self, name: str, command: str, timeout: int = 300) -> ExecResult:
        path = self._mon(name)
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect(str(path))
            # consume the banner prompt
            buf = b""
            while b"(qemu)" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            s.sendall((command + "\n").encode())
            # read until the prompt returns
            buf = b""
            while b"(qemu)" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            s.close()
            text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", buf.decode(errors="replace"))
            return ExecResult(0, text, "")
        except OSError as e:
            return ExecResult(1, "", str(e))

    # -- Backend protocol --------------------------------------------------

    def available(self) -> bool:
        return shutil.which(QEMU) is not None and self.base.is_file() and self.key.is_file()

    def image_exists(self, tag: str) -> bool:
        return self.base.is_file()

    def image_id(self, tag: str) -> str:
        if not self.base.is_file():
            return tag
        st = self.base.stat()
        return f"{self.base.name}:{st.st_size}:{st.st_mtime_ns}"

    def build_image(self, tag: str, context: str) -> ExecResult:
        return ExecResult(1, "", "use `boxes image prep-vm` to build the VM base")

    def _net_state(self, name: str) -> Path:
        return self.run_dir / f"net-{name}.json"

    def _short_id(self, name: str) -> str:
        # Linux interface names are limited to 15 chars; keep br-/tap-/veth-
        # prefixes short enough.
        return hashlib.sha1(name.encode()).hexdigest()[:8]

    def network_create(self, name: str, attacker_pid: int | None = None) -> ExecResult:
        if attacker_pid is None:
            return ExecResult(1, "", "VM attacker networking requires an attacker pid")
        boxes = os.environ.get("BOXES_BIN") or shutil.which("boxes")
        if not boxes:
            return ExecResult(1, "", "`boxes` is not on PATH; install it or set BOXES_BIN")
        user = os.environ.get("SUDO_USER") or getpass.getuser()
        short = self._short_id(name)
        res = self._run(
            [
                "sudo", "-n", boxes, "net", "up", short,
                "--attacker-pid", str(attacker_pid), "--user", user,
            ],
            timeout=60,
        )
        if not res.ok:
            return res
        try:
            info = json.loads(res.stdout)
        except json.JSONDecodeError:
            return ExecResult(1, res.stdout, "could not parse `boxes net up` output")
        self._net_state(name).write_text(json.dumps(info))
        return ExecResult(0, res.stdout, "")

    def network_info(self, name: str) -> dict | None:
        path = self._net_state(name)
        if not path.is_file():
            return None
        return json.loads(path.read_text())

    def network_destroy(self, name: str) -> ExecResult:
        path = self._net_state(name)
        boxes = os.environ.get("BOXES_BIN") or shutil.which("boxes")
        res = ExecResult(0, "", "")
        if boxes:
            short = self._short_id(name)
            res = self._run(["sudo", "-n", boxes, "net", "down", short], timeout=60)
        path.unlink(missing_ok=True)
        return res

    def create(
        self,
        name: str,
        image: str,
        network: str = "none",
        alias: str | None = None,
        provision: bool = False,
    ) -> ExecResult:
        if not self.available():
            return ExecResult(1, "", f"qemu backend not ready ({self.base})")
        overlay = self.run_dir / f"{name}.qcow2"
        log = self.run_dir / f"{name}.log"
        pidfile = self.run_dir / f"{name}.pid"
        mon = self._mon(name)
        res = self._run(
            ["qemu-img", "create", "-q", "-f", "qcow2", "-b", str(self.base), "-F", "qcow2", str(overlay)]
        )
        if not res.ok:
            return res
        port = self._free_port()
        state = {"overlay": str(overlay), "log": str(log), "pidfile": str(pidfile),
                 "port": port, "monitor": str(mon), "name": name}

        prov_tap = None
        prov_ip = None
        prov_short = self._short_id(name)
        if provision:
            boxes = os.environ.get("BOXES_BIN") or shutil.which("boxes")
            if not boxes:
                overlay.unlink(missing_ok=True)
                return ExecResult(1, "", "`boxes` is not on PATH; install it or set BOXES_BIN")
            user = os.environ.get("SUDO_USER") or getpass.getuser()
            res = self._run(
                ["sudo", "-n", boxes, "net", "provision-tap", prov_short, "--user", user],
                timeout=60,
            )
            if not res.ok:
                overlay.unlink(missing_ok=True)
                return res
            try:
                prov_tap = json.loads(res.stdout)["tap"]
            except (json.JSONDecodeError, KeyError):
                overlay.unlink(missing_ok=True)
                return ExecResult(1, res.stdout, "could not parse provision tap output")
            prov_ip = self._provision_ip(name)
            state.update({"provision_tap": prov_tap, "provision_ip": prov_ip,
                          "provision_short": prov_short})
        self._save(name, state)

        args = [
            QEMU,
            "-accel", "tcg,thread=multi",
            "-cpu", "max",
            "-m", "1024", "-smp", "2",
            "-drive", f"file={overlay},if=virtio,format=qcow2",
        ]
        if self.seed.is_file():
            # read-only, otherwise QEMU refuses savevm (all writable disks must
            # support snapshots)
            args += ["-drive", f"file={self.seed},if=virtio,format=raw,readonly=on"]
        # management NIC must be first: the pre-baked netplan configures the
        # first interface (ens3) for DHCP/SSH. restrict=on leaves the SSH
        # hostfwd working but gives the guest no internet/host route.
        args += [
            "-netdev", f"user,id=n0,restrict=on,hostfwd=tcp:127.0.0.1:{port}-:22",
            "-device", "virtio-net-pci,netdev=n0",
        ]
        net_info = self.network_info(network) if network != "none" else None
        if net_info is not None:
            args += [
                "-netdev", f"tap,id=net1,ifname={net_info['tap']},script=no,downscript=no",
                "-device", f"virtio-net-pci,netdev=net1,mac={TAP_MAC}",
            ]
        if prov_tap is not None:
            args += [
                "-netdev", f"tap,id=net2,ifname={prov_tap},script=no,downscript=no",
                "-device", f"virtio-net-pci,netdev=net2,mac={PROV_MAC}",
            ]
        args += [
            "-display", "none",
            "-serial", f"file:{log}",
            "-monitor", f"unix:{mon},server,nowait",
            "-daemonize",
            "-pidfile", str(pidfile),
        ]
        res = self._run(args, timeout=60)
        if not res.ok:
            return res
        if not self._wait_ssh(name):
            tail = log.read_text(errors="replace")[-1500:] if log.is_file() else ""
            return ExecResult(1, "", f"VM did not become reachable\n{tail}")
        if net_info is not None:
            # give the tap NIC its address; find it by MAC (its name may be
            # renamed by udev/cloud-init)
            script = (
                f"dev=$(ip -o link | awk -F': ' '/{TAP_MAC}/ {{print $2; exit}}')\n"
                "test -n \"$dev\"\n"
                f"ip addr replace {net_info['vm_ip']}/24 dev \"$dev\"\n"
                "ip link set \"$dev\" up\n"
            )
            res = self.exec(name, script, timeout=60)
            if not res.ok:
                return ExecResult(1, res.stdout, f"could not configure tap NIC: {res.stderr}")
        if prov_tap is not None:
            script = (
                f"dev=$(ip -o link | awk -F': ' '/{PROV_MAC}/ {{print $2; exit}}')\n"
                "test -n \"$dev\"\n"
                f"ip addr replace {prov_ip}/24 dev \"$dev\"\n"
                "ip link set \"$dev\" up\n"
                "echo \"$dev\"\n"
            )
            res = self.exec(name, script, timeout=60)
            if not res.ok:
                return ExecResult(1, res.stdout, f"could not configure provision NIC: {res.stderr}")
            dev = res.stdout.strip().splitlines()[-1] if res.stdout.strip() else ""
            if dev:
                state["provision_dev"] = dev
                self._save(name, state)
        return ExecResult(0, "", "")

    def _provision_ip(self, name: str) -> str:
        h = int(hashlib.sha1(name.encode()).hexdigest()[:6], 16)
        return f"10.67.0.{10 + h % 200}"

    def seal(self, name: str) -> ExecResult:
        """Disconnect the provision NIC before PoCs (host-only phase)."""
        st = self._load(name)
        dev = st.get("provision_dev")
        if not dev:
            return ExecResult(0, "", "")
        return self.exec(name, f"ip link set {shlex.quote(dev)} down", timeout=30)

    def _free_port(self) -> int:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def exec(
        self,
        name: str,
        script: str,
        user: str | None = None,
        env: dict | None = None,
        workdir: str | None = None,
        timeout: int = 120,
    ) -> ExecResult:
        env = env or {}
        env_prefix = " ".join(f"{k}={shlex.quote(str(v))}" for k, v in env.items())
        if user is None:
            remote = f"sudo -n env {env_prefix} sh -s"
        else:
            remote = f"sudo -n -u {shlex.quote(user)} env {env_prefix} sh -s"
        if workdir:
            remote = f"cd {shlex.quote(workdir)} && {remote}"
        cmd = [*self._ssh_base(name), f"{self.user}@127.0.0.1", remote]
        return self._run(cmd, input=script, timeout=timeout)

    def put(self, name: str, src: str, dst: str) -> ExecResult:
        src_path = Path(src)
        if src_path.is_dir():
            # copy directory *contents* (matching `docker cp src/. dest`)
            tar = subprocess.run(
                ["tar", "-C", str(src_path), "-cf", "-", "."],
                capture_output=True,
            )
            if tar.returncode != 0:
                return ExecResult(tar.returncode, "", tar.stderr.decode(errors="replace"))
            remote = f"sudo -n mkdir -p {shlex.quote(dst)} && sudo -n tar -C {shlex.quote(dst)} -xf -"
            cmd = [*self._ssh_base(name), f"{self.user}@127.0.0.1", remote]
            return self._run_bytes(cmd, tar.stdout)
        return ExecResult(1, "", f"unsupported put source: {src}")

    def _run_bytes(self, args: list[str], data: bytes) -> ExecResult:
        try:
            proc = subprocess.run(args, input=data, capture_output=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired) as e:
            return ExecResult(1, "", str(e))
        return ExecResult(proc.returncode, proc.stdout.decode(errors="replace"),
                          proc.stderr.decode(errors="replace"))

    def snapshot(self, name: str, label: str) -> ExecResult:
        # flush guest page cache so the qcow2 snapshot captures a consistent disk
        self.exec(name, "sync", timeout=60)
        res = self._monitor(name, f"savevm {label}")
        if not res.ok or "Error" in res.stdout or "error" in res.stdout:
            return ExecResult(1, res.stdout, "savevm failed")
        return res

    def restore(self, name: str, label: str) -> ExecResult:
        res = self._monitor(name, f"loadvm {label}")
        if not res.ok or "Error" in res.stdout or "error" in res.stdout:
            return ExecResult(1, res.stdout, "loadvm failed")
        # loadvm resets the guest's network/SSH state; drop and rebuild the master
        self._run([*self._ssh_base(name), "-O", "exit"], timeout=10)
        time.sleep(1)
        if not self._wait_ssh(name, timeout=180):
            return ExecResult(1, res.stdout, "VM not reachable after loadvm")
        return res

    def destroy(self, name: str) -> ExecResult:
        try:
            st = self._load(name)
        except OSError:
            return ExecResult(0, "", "")
        self._run([*self._ssh_base(name), "-O", "exit"], timeout=10)
        pidfile = Path(st.get("pidfile", ""))
        if pidfile.is_file():
            try:
                os.kill(int(pidfile.read_text().strip()), 9)
            except (OSError, ValueError):
                pass
        for path in (st.get("overlay"), st.get("pidfile"), st.get("log"), st.get("monitor")):
            if path:
                Path(path).unlink(missing_ok=True)
        short = st.get("provision_short")
        boxes = os.environ.get("BOXES_BIN") or shutil.which("boxes")
        if short and boxes:
            self._run(["sudo", "-n", boxes, "net", "provision-tap", short, "--down"], timeout=60)
        self._state_path(name).unlink(missing_ok=True)
        Path(self._sock(name)).unlink(missing_ok=True)
        return ExecResult(0, "", "")
