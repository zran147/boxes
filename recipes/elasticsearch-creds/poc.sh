set -eu
body=$(curl -fsS "http://${BOX_HOST}:9200/creds.json")
echo "$body"
echo "$body" | grep -q "$BOX_U" && echo "$body" | grep -q "$BOX_P" \
    || { echo "Elasticsearch credential missing" >&2; exit 1; }
