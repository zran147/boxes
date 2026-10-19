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
import shutil
import subprocess
from pathlib import Path

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")
SUBNET = ipaddress.ip_network("10.66.1.0/24")
DEFAULT_VM_IP = "10.66.1.2"
DEFAULT_ATTACKER_IP = "10.66.1.3"
DEFAULT_HOST_IP = "10.66.1.1"

PROVISION_BR = "br-provision"
PROVISION_VETH = "veth-prov"
PROVISION_VETH_C = "veth-provc"
PROVISION_IP = "10.67.0.2"


def _ensure_forward(br: str) -> None:
    if not shutil.which("iptables"):
        return
    check = subprocess.run(
        ["iptables", "-C", "FORWARD", "-i", br, "-o", br, "-j", "ACCEPT"],
        capture_output=True,
    )
    if check.returncode != 0:
        _try(["iptables", "-I", "FORWARD", "-i", br, "-o", br, "-j", "ACCEPT"])


def _ensure_bridge(br: str) -> None:
    _try(["ip", "link", "add", br, "type", "bridge"])
    _run(["ip", "link", "set", br, "up"])
    _ensure_forward(br)


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
    host_ip: str | None = None,
) -> tuple[int, str, str, str, str | None]:
    if not NAME_RE.match(name):
        raise NetError(f"invalid machine id {name!r}")
    if len(name) > 9:
        raise NetError(
            f"machine id {name!r} is too long; interface names are limited to 15 "
            f"characters (br-/tap-/veth- prefixes)"
        )
    pid = int(attacker_pid)
    if pid <= 0 or not Path(f"/proc/{pid}").exists():
        raise NetError(f"attacker pid {pid} does not exist")
    try:
        pwd.getpwnam(user)
    except KeyError as e:
        raise NetError(f"unknown user {user!r}") from e
    try:
        vm = ipaddress.ip_address(vm_ip)
    except ValueError as e:
        raise NetError(f"invalid vm ip {vm_ip!r}") from e
    network = ipaddress.ip_network(f"{vm_ip}/24", strict=False)
    addresses = [(vm_ip, "vm"), (attacker_ip, "attacker")]
    if host_ip is not None:
        addresses.append((host_ip, "host"))
    seen: set[str] = set()
    for addr, label in addresses:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError as e:
            raise NetError(f"invalid {label} ip {addr!r}") from e
        if ip.version != 4:
            raise NetError(f"{label} ip {addr} must be IPv4")
        if ip not in network:
            raise NetError(f"{label} ip {addr} must be inside {network}")
        if ip == network.network_address or ip == network.broadcast_address:
            raise NetError(f"{label} ip {addr} is a network/broadcast address")
        if label != "vm" and addr in seen:
            raise NetError(f"{label} ip {addr} duplicates another address")
        seen.add(addr)
    if vm_ip == attacker_ip:
        raise NetError("vm and attacker ips must differ")
    return pid, user, vm_ip, attacker_ip, host_ip


def up(
    name: str,
    attacker_pid: int,
    user: str | None = None,
    vm_ip: str = DEFAULT_VM_IP,
    attacker_ip: str = DEFAULT_ATTACKER_IP,
    host_ip: str | None = None,
) -> dict:
    if os.geteuid() != 0:
        raise NetError("must run as root; use `sudo boxes net up ...`")
    user = user or os.environ.get("SUDO_USER") or getpass.getuser()
    pid, user, vm_ip, attacker_ip, host_ip = _validate(
        name, attacker_pid, user, vm_ip, attacker_ip, host_ip
    )

    br = f"br-{name}"
    tap = f"tap-{name}"
    veth = f"veth-{name}"
    veth_c = f"veth-{name}c"

    down(name)  # best effort: clear leftovers from a crashed run

    _run(["ip", "link", "add", br, "type", "bridge"])
    _run(["ip", "link", "set", br, "up"])
    # Docker enables br_netfilter, so bridged IP traffic traverses FORWARD,
    # which Docker's policy drops for unknown bridges. Allow this bridge only.
    _ensure_forward(br)
    if host_ip is not None:
        _run(["ip", "addr", "replace", f"{host_ip}/24", "dev", br])
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
        "host_ip": host_ip,
        "attacker_if": "eth0",
    }


def down(name: str) -> dict:
    if os.geteuid() != 0:
        raise NetError("must run as root; use `sudo boxes net down ...`")
    if not NAME_RE.match(name):
        raise NetError(f"invalid machine id {name!r}")
    if len(name) > 9:
        raise NetError(f"machine id {name!r} is too long for interface names")
    br = f"br-{name}"
    if shutil.which("iptables"):
        _try(["iptables", "-D", "FORWARD", "-i", br, "-o", br, "-j", "ACCEPT"])
    for dev in (f"tap-{name}", f"veth-{name}", f"br-{name}"):
        _try(["ip", "link", "del", dev])
    return {"machine": name, "removed": True}


# --- shared provisioning network -------------------------------------------


def provision_up(proxy_pid: int) -> dict:
    if os.geteuid() != 0:
        raise NetError("must run as root; use `sudo boxes net provision-up ...`")
    pid = int(proxy_pid)
    if pid <= 0 or not Path(f"/proc/{pid}").exists():
        raise NetError(f"proxy pid {pid} does not exist")

    _ensure_bridge(PROVISION_BR)
    _try(["ip", "link", "del", PROVISION_VETH])
    _run(["ip", "link", "add", PROVISION_VETH, "type", "veth", "peer", "name", PROVISION_VETH_C])
    _run(["ip", "link", "set", PROVISION_VETH, "master", PROVISION_BR])
    _run(["ip", "link", "set", PROVISION_VETH, "up"])
    _run(["ip", "link", "set", PROVISION_VETH_C, "netns", str(pid)])
    # Do not use eth1: Docker may later attach the egress network and choose
    # the next free ethN name itself. A stable non-eth name avoids conflicts.
    _run(["nsenter", "-t", str(pid), "-n", "ip", "link", "set", PROVISION_VETH_C, "name", "prov0"])
    _run(["nsenter", "-t", str(pid), "-n", "ip", "addr", "replace", f"{PROVISION_IP}/24", "dev", "prov0"])
    _run(["nsenter", "-t", str(pid), "-n", "ip", "link", "set", "prov0", "up"])
    return {"bridge": PROVISION_BR, "veth": PROVISION_VETH, "proxy_ip": PROVISION_IP}


def provision_down() -> dict:
    if os.geteuid() != 0:
        raise NetError("must run as root; use `sudo boxes net provision-down`")
    _try(["ip", "link", "del", PROVISION_VETH])
    # keep br-provision and its FORWARD rule: other machines may still use it
    return {"removed": PROVISION_VETH}


def provision_tap(name: str, user: str | None = None) -> dict:
    if os.geteuid() != 0:
        raise NetError("must run as root; use `sudo boxes net provision-tap ...`")
    if not NAME_RE.match(name):
        raise NetError(f"invalid machine id {name!r}")
    if len(name) > 9:
        raise NetError(f"machine id {name!r} is too long for interface names")
    user = user or os.environ.get("SUDO_USER") or getpass.getuser()
    try:
        pwd.getpwnam(user)
    except KeyError as e:
        raise NetError(f"unknown user {user!r}") from e

    tap = f"tap-p-{name}"
    _ensure_bridge(PROVISION_BR)
    _try(["ip", "link", "del", tap])
    _run(["ip", "tuntap", "add", "dev", tap, "mode", "tap", "user", user])
    _run(["ip", "link", "set", tap, "master", PROVISION_BR])
    _run(["ip", "link", "set", tap, "up"])
    return {"tap": tap, "bridge": PROVISION_BR}


def provision_tap_down(name: str) -> dict:
    if os.geteuid() != 0:
        raise NetError("must run as root; use `sudo boxes net provision-tap ... --down`")
    if len(name) > 9:
        raise NetError(f"machine id {name!r} is too long for interface names")
    _try(["ip", "link", "del", f"tap-p-{name}"])
    return {"removed": f"tap-p-{name}"}


def _link_exists(dev: str) -> bool:
    return subprocess.run(["ip", "link", "show", dev], capture_output=True).returncode == 0


def attach_attacker(
    name: str, attacker_pid: int, attacker_ip: str = DEFAULT_ATTACKER_IP
) -> dict:
    """Attach a freshly recreated attacker container to an existing attack bridge."""
    if os.geteuid() != 0:
        raise NetError("must run as root; use `sudo boxes net attach-attacker ...`")
    if not NAME_RE.match(name):
        raise NetError(f"invalid machine id {name!r}")
    if len(name) > 9:
        raise NetError(f"machine id {name!r} is too long for interface names")
    pid = int(attacker_pid)
    if pid <= 0 or not Path(f"/proc/{pid}").exists():
        raise NetError(f"attacker pid {pid} does not exist")
    br = f"br-{name}"
    if not _link_exists(br):
        raise NetError(f"attack bridge {br} does not exist")
    try:
        ipaddress.ip_address(attacker_ip)
    except ValueError as e:
        raise NetError(f"invalid attacker ip {attacker_ip!r}") from e

    veth = f"veth-{name}"
    veth_c = f"veth-{name}c"
    _try(["ip", "link", "del", veth])
    _run(["ip", "link", "add", veth, "type", "veth", "peer", "name", veth_c])
    _run(["ip", "link", "set", veth, "master", br])
    _run(["ip", "link", "set", veth, "up"])
    _run(["ip", "link", "set", veth_c, "netns", str(pid)])
    _run(["nsenter", "-t", str(pid), "-n", "ip", "link", "set", veth_c, "name", "eth0"])
    _run(["nsenter", "-t", str(pid), "-n", "ip", "addr", "replace", f"{attacker_ip}/24", "dev", "eth0"])
    _run(["nsenter", "-t", str(pid), "-n", "ip", "link", "set", "eth0", "up"])
    return {"bridge": br, "attacker_ip": attacker_ip}
