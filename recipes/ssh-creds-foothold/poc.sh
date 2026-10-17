#!/bin/sh
# Prove the credentials give an interactive shell and the user flag.
set -eu
home=$(getent passwd "$BOX_U" | cut -d: -f6)
[ -n "$home" ] || home="/home/$BOX_U"
out=$(sshpass -p "$BOX_P" ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 \
    "$BOX_U@$BOX_HOST" "id; cat '$home/user.txt'")
echo "$out"
echo "$out" | grep -q 'FLAG{user-' || { echo "could not read user flag over SSH" >&2; exit 1; }
