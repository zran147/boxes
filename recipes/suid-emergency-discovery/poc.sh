set -eu
found=$(find / -xdev -perm -4000 -type f 2>/dev/null | grep -E '/emergency$' || true)
[ -n "$found" ] || { echo "no SUID emergency binary found" >&2; exit 1; }
echo "found SUID binary: $found"
