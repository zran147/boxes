set -eu
out=$(/usr/local/bin/docker-security -p -c 'id -u; cat /root/root.txt' 2>&1)
echo "$out"
echo "$out" | grep -q 'FLAG{root-' || { echo "docker-security helper did not give root" >&2; exit 1; }
