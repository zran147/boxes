set -eu
out=$(dig +short -p 8053 "@${BOX_HOST}" "$BOX_VHOST" 2>&1)
echo "$out"
echo "$out" | grep -q '127.0.0.1' || { echo "zone transfer did not reveal the host" >&2; exit 1; }
