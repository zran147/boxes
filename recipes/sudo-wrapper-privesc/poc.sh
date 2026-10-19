set -eu
binary="${BOX_BINARY:?BOX_BINARY is not set}"
out=$(sudo -n "/usr/local/bin/$binary" -c 'id -u; cat /root/root.txt' 2>&1)
echo "$out"
echo "$out" | grep -q 'FLAG{root-' || { echo "sudo wrapper did not give root" >&2; exit 1; }
