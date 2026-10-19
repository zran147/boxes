set -eu
jar=$(mktemp)
curl -fsS -o "$jar" "http://${BOX_HOST}:8086/${BOX_PATH}/BlockCore.jar"
out=$(unzip -p "$jar" creds.txt)
echo "$out"
echo "$out" | grep -q "DB_USER=$BOX_U" || { echo "JAR user missing" >&2; exit 1; }
echo "$out" | grep -q "DB_PASS=$BOX_P" || { echo "JAR password missing" >&2; exit 1; }
rm -f "$jar"
