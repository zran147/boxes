"""Privileged network helper for VM attacker PoCs.

`boxes net up` / `boxes net down` are the only commands that need root. They
set up a per-machine bridge + tap + veth so a Docker attacker container and a
QEMU VM share an L2 segment.

The helper is intentionally narrow: it validates the machine id, the attacker
pid, the interface addresses, and only runs a fixed set of `ip`/`nsenter`
commands. Put it behind a sudoers rule (see README).
"""

from __future__ import annotations

import getpass
import ipaddress
import os
import pwd
import re
import subprocess
from pathlib import Path

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")
SUBNET = ipaddress.ip_network("10.66.1.0/24")
DEFAULT_VM_IP = "10.66.1.2"
DEFAULT_ATTACKER_IP = "10.66.1.3"


class NetError(RuntimeError):
    pass


def _run(args: list[str]) -> subprocess.CompletedProcess:
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise NetError(f"{' '.join(args)}: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc


def _try(args: list[str]) -> None:
    subprocess.run(args, capture_output=True, text=True)


def _validate(
    name: str,
    attacker_pid: int,
    user: str,
    vm_ip: str,
    attacker_ip: str,
) -> tuple[int, str, str, str]:
    if not NAME_RE.match(name):
        raise NetError(f"invalid machine id {name!r}")
    pid = int(attacker_pid)
    if pid <= 0 or not Path(f"/proc/{pid}").exists():
        raise NetError(f"attacker pid {pid} does not exist")
    try:
        pwd.getpwnam(user)
    except KeyError as e:
        raise NetError(f"unknown user {user!r}") from e
    for addr, label in ((vm_ip, "vm"), (attacker_ip, "attacker")):
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError as e:
            raise NetError(f"invalid {label} ip {addr!r}") from e
        if ip not in SUBNET:
            raise NetError(f"{label} ip {addr} must be inside {SUBNET}")
        if ip == SUBNET.network_address or ip == SUBNET.broadcast_address:
            raise NetError(f"{label} ip {addr} is a network/broadcast address")
    if vm_ip == attacker_ip:
        raise NetError("vm and attacker ips must differ")
    return pid, user, vm_ip, attacker_ip


def up(
    name: str,
    attacker_pid: int,
    user: str | None = None,
    vm_ip: str = DEFAULT_VM_IP,
    attacker_ip: str = DEFAULT_ATTACKER_IP,
) -> dict:
    if os.geteuid() != 0:
        raise NetError("must run as root; use `sudo boxes net up ...`")
    user = user or os.environ.get("SUDO_USER") or getpass.getuser()
    pid, user, vm_ip, attacker_ip = _validate(name, attacker_pid, user, vm_ip, attacker_ip)

    br = f"br-{name}"
    tap = f"tap-{name}"
    veth = f"veth-{name}"
    veth_c = f"veth-{name}c"

    down(name)  # best effort: clear leftovers from a crashed run

    _run(["ip", "link", "add", br, "type", "bridge"])
    _run(["ip", "link", "set", br, "up"])
    _run(["ip", "tuntap", "add", "dev", tap, "mode", "tap", "user", user])
    _run(["ip", "link", "set", tap, "master", br])
    _run(["ip", "link", "set", tap, "up"])
    _run(["ip", "link", "add", veth, "type", "veth", "peer", "name", veth_c])
    _run(["ip", "link", "set", veth, "master", br])
    _run(["ip", "link", "set", veth, "up"])
    _run(["ip", "link", "set", veth_c, "netns", str(pid)])
    _run(["nsenter", "-t", str(pid), "-n", "ip", "link", "set", veth_c, "name", "eth0"])
    _run(["nsenter", "-t", str(pid), "-n", "ip", "addr", "add", f"{attacker_ip}/24", "dev", "eth0"])
    _run(["nsenter", "-t", str(pid), "-n", "ip", "link", "set", "eth0", "up"])

    return {
        "machine": name,
        "bridge": br,
        "tap": tap,
        "vm_ip": vm_ip,
        "attacker_ip": attacker_ip,
        "attacker_if": "eth0",
    }


def down(name: str) -> dict:
    if os.geteuid() != 0:
        raise NetError("must run as root; use `sudo boxes net down ...`")
    if not NAME_RE.match(name):
        raise NetError(f"invalid machine id {name!r}")
    for dev in (f"tap-{name}", f"veth-{name}", f"br-{name}"):
        _try(["ip", "link", "del", dev])
    return {"machine": name, "removed": True}
