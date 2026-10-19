set -eu
out=$(sudo -n -l 2>&1)
echo "$out"
echo "$out" | grep -q 'monitor.sh' || { echo "monitor sudo rule not found" >&2; exit 1; }
