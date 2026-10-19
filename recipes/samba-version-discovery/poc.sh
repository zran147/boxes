set -eu
body=$(curl -fsS "http://${BOX_HOST}:8444/")
echo "$body"
echo "$body" | grep -q 'Samba 3.0.20' || { echo "Samba banner not found" >&2; exit 1; }
