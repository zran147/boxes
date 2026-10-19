set -eu
out=$(sudo -n sh -c 'id -u; cat /root/root.txt' 2>&1)
echo "$out"
echo "$out" | grep -q 'FLAG{root-' || { echo "sudo did not return root" >&2; exit 1; }
