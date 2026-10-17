"""Prepare a pre-baked VM base image.

Boots the Ubuntu cloud image once with a cloud-init seed, waits for first boot
to finish, then powers off. The resulting overlay is used as the backing image
for every machine, so per-machine boots skip cloud-init's first-boot work.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

from .backends.base import ExecResult

CLOUD_URL = "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
USER = "boxes"


def _run(args: list[str], *, timeout: int = 120) -> ExecResult:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return ExecResult(127, "", f"{args[0]}: not found")
    except (OSError, subprocess.TimeoutExpired) as e:
        return ExecResult(1, "", str(e))
    return ExecResult(proc.returncode, proc.stdout, proc.stderr)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_ssh(port: int, key: Path, timeout: int) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        res = _run(
            [
                "ssh", "-i", str(key), "-p", str(port),
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=3",
                "-o", "BatchMode=yes",
                f"{USER}@127.0.0.1", "true",
            ],
            timeout=10,
        )
        if res.ok:
            return True
        time.sleep(3)
    return False


def prepare_base(store: Path, rebuild: bool = False, boot_timeout: int = 600) -> ExecResult:
    store = Path(store)
    store.mkdir(parents=True, exist_ok=True)
    prebaked = store / "base-prebaked.qcow2"
    if prebaked.is_file() and not rebuild:
        return ExecResult(0, f"{prebaked} already exists", "")

    for tool in ("qemu-system-x86_64", "qemu-img", "cloud-localds", "ssh-keygen"):
        if shutil.which(tool) is None:
            return ExecResult(1, "", f"missing tool: {tool}")

    key = store / "boxes_key"
    if not key.is_file():
        res = _run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
        if not res.ok:
            return res

    cloud = store / "jammy-base.img"
    if not cloud.is_file():
        res = _run(["curl", "-L", "-sS", "-o", str(cloud), CLOUD_URL], timeout=1800)
        if not res.ok:
            return res

    pub = (store / "boxes_key.pub").read_text().strip()
    (store / "user-data").write_text(
        "#cloud-config\n"
        "users:\n"
        "  - default\n"
        f"  - name: {USER}\n"
        "    sudo: ALL=(ALL) NOPASSWD:ALL\n"
        "    shell: /bin/bash\n"
        "    lock_passwd: false\n"
        "    ssh_authorized_keys:\n"
        f"      - {pub}\n"
        "ssh_pwauth: false\n"
        "package_update: false\n"
        "runcmd:\n"
        '  - [ sh, -c, "echo ready > /var/lib/boxes-ready" ]\n'
    )
    (store / "meta-data").write_text("instance-id: boxes-vm-1\nlocal-hostname: boxes-vm\n")
    seed = store / "seed.iso"
    res = _run(["cloud-localds", str(seed), str(store / "user-data"), str(store / "meta-data")])
    if not res.ok:
        return res

    work = store / "prep.qcow2"
    work.unlink(missing_ok=True)
    res = _run(
        ["qemu-img", "create", "-q", "-f", "qcow2", "-b", str(cloud.resolve()), "-F", "qcow2", str(work)]
    )
    if not res.ok:
        return res
    res = _run(["qemu-img", "resize", "-q", str(work), "8G"])
    if not res.ok:
        return res

    port = _free_port()
    log = store / "prep-console.log"
    pidfile = store / "prep.pid"
    monitor = store / "prep.mon"
    for path in (log, pidfile, monitor):
        Path(path).unlink(missing_ok=True)
    res = _run(
        [
            "qemu-system-x86_64",
            "-accel", "tcg,thread=multi",
            "-cpu", "max",
            "-m", "1024", "-smp", "2",
            "-drive", f"file={work},if=virtio,format=qcow2",
            "-drive", f"file={seed},if=virtio,format=raw,readonly=on",
            "-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:22",
            "-device", "virtio-net-pci,netdev=n0",
            "-display", "none",
            "-serial", f"file:{log}",
            "-monitor", f"unix:{monitor},server,nowait",
            "-daemonize",
            "-pidfile", str(pidfile),
        ],
        timeout=60,
    )
    if not res.ok:
        return res
    if not _wait_ssh(port, key, boot_timeout):
        tail = log.read_text(errors="replace")[-1500:] if log.is_file() else ""
        return ExecResult(1, "", f"prep VM did not boot\n{tail}")

    # wait for cloud-init, then shut down cleanly
    _run(
        [
            "ssh", "-i", str(key), "-p", str(port),
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            f"{USER}@127.0.0.1", "sudo cloud-init status --wait || true",
        ],
        timeout=900,
    )
    _run(
        [
            "ssh", "-i", str(key), "-p", str(port),
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            f"{USER}@127.0.0.1", "sudo poweroff",
        ],
        timeout=60,
    )
    deadline = time.time() + 180
    pid = None
    while time.time() < deadline:
        try:
            pid = int(pidfile.read_text().strip())
            os.kill(pid, 0)
        except (OSError, ValueError):
            pid = None
            break
        time.sleep(2)
    if pid is not None:
        try:
            os.kill(pid, 9)
        except OSError:
            pass

    prebaked.unlink(missing_ok=True)
    work.replace(prebaked)
    for path in (log, pidfile, monitor):
        Path(path).unlink(missing_ok=True)
    return ExecResult(0, f"prepared {prebaked}", "")
