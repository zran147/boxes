set -eu
p="${BOX_PATH:-secret}"; p="${p#/}"; p="${p%/}"
mkdir -p /var/www/html "$p"
if ! curl -fsS -o /dev/null http://127.0.0.1/ 2>/dev/null; then
    nohup python3 -m http.server 80 --directory /var/www/html >/var/log/web.log 2>&1 &
    sleep 1
fi
mkdir -p "/var/www/html/$p"
printf 'Joomla admin: %s / %s\n' "$BOX_U" "$BOX_P" > "/var/www/html/$p/secret.txt"
