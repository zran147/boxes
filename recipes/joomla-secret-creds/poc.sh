set -eu
body=$(curl -fsS "http://${BOX_HOST}/${BOX_PATH}/secret.txt")
echo "$body"
echo "$body" | grep -q "$BOX_U" && echo "$body" | grep -q "$BOX_P" \
    || { echo "Joomla secret is missing" >&2; exit 1; }
