set -eu
body=$(curl -fsS "http://${BOX_HOST}:8447/creds.txt")
echo "$body"
echo "$body" | grep -q "USER=$BOX_U" && echo "$body" | grep -q "PASS=$BOX_P" \
    || { echo "share credentials missing" >&2; exit 1; }
