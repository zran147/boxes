#!/bin/sh
# VM-only proof: PID 1 is systemd and a kernel boot image is present.
set -eu

pid1=$(cat /proc/1/comm)
[ "$pid1" = "systemd" ] || {
    echo "pid1 is '$pid1', not systemd; this is not the VM product" >&2
    exit 1
}

kernel=$(uname -r)
[ -n "$kernel" ] || { echo "uname -r is empty" >&2; exit 1; }

grep -q 'BOOT_IMAGE=' /proc/cmdline || {
    echo "no BOOT_IMAGE in /proc/cmdline" >&2
    exit 1
}

echo "vm kernel: $kernel (pid1=$pid1)"
