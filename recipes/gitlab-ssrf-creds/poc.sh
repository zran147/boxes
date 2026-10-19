set -eu
body=$(curl -fsS "http://${BOX_HOST}:8095/creds.txt")
echo "$body"
echo "$body" | grep -q "GITLAB_USER=dexter" && echo "$body" | grep -q "GITLAB_PASS=$BOX_P" \
    || { echo "GitLab credential missing" >&2; exit 1; }
