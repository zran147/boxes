#!/bin/sh
# Runs in the attacker container; reaches the VM over the tap network.
set -eu
out=$(sshpass -p "$BOX_P" ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=10 \
    "$BOX_U@$BOX_HOST" 'id; cat ~/user.txt')
echo "$out"
echo "$out" | grep -q 'FLAG{user-' || { echo "could not read user flag over SSH" >&2; exit 1; }
