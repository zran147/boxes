set -eu
body=$(curl -fsS "http://${BOX_HOST}:8091/config.php")
echo "$body"
echo "$body" | grep -q "ADMINER_USER=$BOX_U" && echo "$body" | grep -q "ADMINER_PASS=$BOX_P" \
    || { echo "Adminer credentials missing" >&2; exit 1; }
