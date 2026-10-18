"""Package proxy / cache lifecycle.

The proxy is a long-lived container with a persistent cache. Targets reach it
on the shared `br-provision` bridge (VMs) or the `boxes-provision` Docker
network (containers); only the proxy has egress.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from .backends.base import ExecResult
from .images import PROJECT_ROOT

IMAGE = "boxes/proxy:latest"
CONTAINER = "boxes-proxy"
NETWORK = "boxes-provision"
CACHE_VOLUME = "boxes-proxy-cache"
PROXY_IP = "10.67.0.2"
PROXY_PORT = 3128
ARTIFACT_PORT = 8000
ARTIFACTS_DIR = PROJECT_ROOT / ".boxes-cache" / "artifacts"
IMAGE_CONTEXT = PROJECT_ROOT / "images" / "proxy"


def _run(args: list[str], timeout: int = 180) -> ExecResult:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return ExecResult(127, "", f"{args[0]}: not found")
    except (OSError, subprocess.TimeoutExpired) as e:
        return ExecResult(1, "", str(e))
    return ExecResult(proc.returncode, proc.stdout, proc.stderr)


def proxy_url() -> str:
    return f"http://{PROXY_IP}:{PROXY_PORT}"


def artifacts_url() -> str:
    return f"http://{PROXY_IP}:{ARTIFACT_PORT}"


def is_up() -> bool:
    res = _run(["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER], timeout=30)
    if not res.ok or res.stdout.strip() != "true":
        return False
    # the veth must be attached to br-provision
    link = _run(["ip", "link", "show", "veth-prov"], timeout=10)
    return link.ok


def up(rebuild: bool = False) -> ExecResult:
    if not shutil.which("docker"):
        return ExecResult(1, "", "docker is not installed")
    image = _run(["docker", "image", "inspect", IMAGE], timeout=30)
    if rebuild or not image.ok:
        res = _run(["docker", "build", "-t", IMAGE, str(IMAGE_CONTEXT)], timeout=1800)
        if not res.ok:
            return res

    if not _run(["docker", "network", "inspect", NETWORK], timeout=30).ok:
        res = _run(["docker", "network", "create", NETWORK], timeout=60)
        if not res.ok:
            return res

    _run(["docker", "rm", "-f", CONTAINER], timeout=60)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    res = _run(
        [
            "docker", "run", "-d",
            "--name", CONTAINER,
            "--network", NETWORK,
            "--network-alias", "boxes-proxy",
            "-v", f"{CACHE_VOLUME}:/var/spool/squid",
            "-v", f"{ARTIFACTS_DIR}:/srv/artifacts",
            IMAGE,
        ],
        timeout=180,
    )
    if not res.ok:
        return res

    pid = _run(["docker", "inspect", "-f", "{{.State.Pid}}", CONTAINER], timeout=30)
    if not pid.ok or not pid.stdout.strip():
        _run(["docker", "rm", "-f", CONTAINER])
        return ExecResult(1, "", f"could not determine proxy pid: {pid.output()}")

    boxes = os.environ.get("BOXES_BIN") or shutil.which("boxes")
    if not boxes:
        _run(["docker", "rm", "-f", CONTAINER])
        return ExecResult(1, "", "`boxes` is not on PATH; install it or set BOXES_BIN")
    res = _run(["sudo", "-n", boxes, "net", "provision-up", pid.stdout.strip()], timeout=60)
    if not res.ok:
        _run(["docker", "rm", "-f", CONTAINER])
        return res
    return ExecResult(0, json.dumps({
        "container": CONTAINER,
        "network": NETWORK,
        "url": proxy_url(),
        "artifacts_url": artifacts_url(),
    }), "")


def down(clean: bool = False) -> ExecResult:
    pid = _run(["docker", "inspect", "-f", "{{.State.Pid}}", CONTAINER], timeout=30)
    boxes = os.environ.get("BOXES_BIN") or shutil.which("boxes")
    if pid.ok and pid.stdout.strip() and boxes:
        _run(["sudo", "-n", boxes, "net", "provision-down", pid.stdout.strip()], timeout=60)
    _run(["docker", "rm", "-f", CONTAINER], timeout=60)
    if clean:
        _run(["docker", "volume", "rm", "-f", CACHE_VOLUME], timeout=60)
        shutil.rmtree(ARTIFACTS_DIR, ignore_errors=True)
    return ExecResult(0, "", "")


def status() -> dict:
    return {
        "running": is_up(),
        "container": CONTAINER,
        "network": NETWORK,
        "proxy_ip": PROXY_IP,
        "url": proxy_url(),
        "artifacts_url": artifacts_url(),
        "cache_volume": CACHE_VOLUME,
        "artifacts_dir": str(ARTIFACTS_DIR),
    }
