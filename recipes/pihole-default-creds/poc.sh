set -eu
out=$(sshpass -p raspberry ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 pi@"$BOX_HOST" 'id -un')
echo "$out"
echo "$out" | grep -qx pi || { echo "default Pi credentials failed" >&2; exit 1; }
