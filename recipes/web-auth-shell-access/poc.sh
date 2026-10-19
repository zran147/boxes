set -eu
u="${BOX_U:?BOX_U is not set}"
p="${BOX_P:?BOX_P is not set}"
jar=$(mktemp)
curl -fsS -c "$jar" -d "username=$u&password=$p" "http://${BOX_HOST}:8098/${BOX_PATH}/login" >/dev/null
out=$(curl -fsS -b "$jar" "http://${BOX_HOST}:8098/${BOX_PATH}/run?cmd=id")
echo "$out"
echo "$out" | grep -q 'uid=' || { echo "authenticated shell did not execute" >&2; exit 1; }
rm -f "$jar"
