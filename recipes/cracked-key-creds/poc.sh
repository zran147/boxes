set -eu
out=$(cat /opt/id_rsa.bak)
echo "$out"
echo "$out" | grep -q "MATT_PASSWORD=$BOX_P" || { echo "backup key password missing" >&2; exit 1; }
