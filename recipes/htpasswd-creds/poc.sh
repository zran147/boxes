set -eu
out=$(cat /var/nostromo/conf/.htpasswd)
echo "$out"
echo "$out" | grep -q "david:$BOX_P" || { echo "htpasswd password missing" >&2; exit 1; }
