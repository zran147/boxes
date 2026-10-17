#!/bin/sh
# Serve a web root with one unlinked directory on it.
set -eu
p="${BOX_PATH:?BOX_PATH is not set}"
p="${p#/}"; p="${p%/}"

mkdir -p /var/www/html
if ! curl -fsS -o /dev/null http://127.0.0.1/ 2>/dev/null; then
    nohup python3 -m http.server 80 --directory /var/www/html >/var/log/web.log 2>&1 &
    sleep 1
fi

mkdir -p "/var/www/html/$p"
echo "internal notes" > "/var/www/html/$p/index.html"
