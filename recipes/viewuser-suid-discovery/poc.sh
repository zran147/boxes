set -eu
found=$(find / -xdev -perm -4000 -type f 2>/dev/null | grep -E '/viewuser$' || true)
[ -n "$found" ] || { echo "no SUID viewuser found" >&2; exit 1; }
echo "found SUID binary: $found"
