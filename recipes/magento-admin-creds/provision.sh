set -eu
p="${BOX_PATH:-magento}"; p="${p#/}"; p="${p%/}"
mkdir -p /var/www/html "$p"
if ! curl -fsS -o /dev/null http://127.0.0.1/ 2>/dev/null; then
    nohup python3 -m http.server 80 --directory /var/www/html >/var/log/web.log 2>&1 &
    sleep 1
fi
mkdir -p "/var/www/html/$p"
printf 'admin_user=%s\nadmin_pass=%s\n' "${BOX_U:-admin}" "${BOX_P:-123}" > "/var/www/html/$p/local.xml"
