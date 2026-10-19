set -eu
out=$(cat /var/www/html/ona/local/config/database_settings.inc.php)
echo "$out"
echo "$out" | grep -q "db_passwd=$BOX_P" || { echo "ONA database password missing" >&2; exit 1; }
