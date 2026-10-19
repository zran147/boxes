set -eu
body=$(curl -fsS "http://${BOX_HOST}:8066/")
echo "$body"
echo "$body" | grep -q 'UnrealIRCd 3.2.8.1' || { echo "IRC banner missing" >&2; exit 1; }
