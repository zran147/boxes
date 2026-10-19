set -eu
out=$(sudo -n -l 2>&1)
echo "$out"
echo "$out" | grep -q 'NOPASSWD: ALL' || { echo "unrestricted sudo rule not found" >&2; exit 1; }
