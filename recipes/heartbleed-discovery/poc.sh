set -eu
body=$(curl -fsS "http://${BOX_HOST}:8442/")
echo "$body"
echo "$body" | grep -q 'heartbleed' || { echo "Heartbleed banner not found" >&2; exit 1; }
