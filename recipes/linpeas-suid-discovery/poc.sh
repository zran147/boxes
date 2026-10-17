#!/bin/sh
# Prove the knowledge is real: running as the foothold user, we can find a
# SUID copy of the named binary.
set -eu
bin="${BOX_BINARY:?BOX_BINARY is not set}"
found=$(find / -xdev -perm -4000 -type f 2>/dev/null | grep -E "/${bin}$" || true)
[ -n "$found" ] || { echo "no SUID $bin found" >&2; exit 1; }
echo "found SUID binary: $found"
