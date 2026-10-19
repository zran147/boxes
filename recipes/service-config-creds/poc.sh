set -eu
out=$(cat /var/www/conf/database.conf)
echo "$out"
echo "$out" | grep -q "db_user=$BOX_DB_USER" && echo "$out" | grep -q "db_pass=$BOX_DB_PASS" \
    || { echo "database credentials missing" >&2; exit 1; }
