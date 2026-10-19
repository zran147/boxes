set -eu
out=$(cat /home/professor/creds.txt)
echo "$out"
echo "$out" | grep -q "SSH_PASS=$BOX_P" || { echo "professor credential missing" >&2; exit 1; }
