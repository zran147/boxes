set -eu
body=$(curl -fsS "http://${BOX_HOST}/${BOX_PATH}/local.xml")
echo "$body"
echo "$body" | grep -q "admin_user=$BOX_U" && echo "$body" | grep -q "admin_pass=$BOX_P" \
    || { echo "Magento admin credential missing" >&2; exit 1; }
