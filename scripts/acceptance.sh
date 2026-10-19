#!/usr/bin/env bash
# Full acceptance run. Assumes `boxes` is installed, Docker works, and the
# sudoers rule for `boxes net *` is in place (needed by `boxes proxy up`).
#
#   scripts/acceptance.sh
#   scripts/acceptance.sh --with-vm
#
# The VM half uses TCG unless KVM is available; it is intentionally opt-in.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== unit =="
python3 -m pytest -q

echo "== lint =="
boxes lint

echo "== images =="
boxes image build --os ubuntu-22.04
boxes image tools --check

echo "== proxy =="
boxes proxy up

for os in ubuntu-22.04 debian-12 ubuntu-24.04; do
    echo "== docker matrix: $os =="
    boxes image build --os "$os"
    boxes verify --all --os "$os" --jobs 4
done

echo "== docker integration =="
BOXES_DOCKER_TESTS=1 python3 -m pytest -m docker -q

if [[ "${1:-}" == "--with-vm" ]]; then
    echo "== qemu =="
    for os in ubuntu-22.04 debian-12 ubuntu-24.04; do
        BOXES_VM_BOOT_TIMEOUT=1800 boxes image build --backend qemu --os "$os"
    done
    for os in ubuntu-22.04 debian-12 ubuntu-24.04; do
        BOXES_VM_BOOT_TIMEOUT=1800 boxes verify --recipe vm-kernel-probe \
            --backend qemu --os "$os" --no-cache
    done
    BOXES_VM_BOOT_TIMEOUT=1800 boxes verify --machine --backend qemu --os debian-12 \
        --to-user 2 --to-root 1 --seed 0 --no-cache
    BOXES_VM_BOOT_TIMEOUT=1800 boxes verify --machine --backend qemu --os ubuntu-24.04 \
        --to-user 2 --to-root 1 --seed 0 --no-cache
fi
