set -eu
out=$(cat /var/log/audit/audit.log)
echo "$out"
echo "$out" | grep -q "shaun password=$BOX_P" || { echo "audit log password missing" >&2; exit 1; }
