set -eu
out=$(curl -fsS "http://${BOX_HOST}:8093/laravel/run?cmd=id")
echo "$out"
echo "$out" | grep -q 'uid=' || { echo "Laravel deserialization did not execute" >&2; exit 1; }
