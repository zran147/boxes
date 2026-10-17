#!/bin/sh
# Serve an exposed .env file containing credentials.
set -eu
mkdir -p /var/www/html
if ! curl -fsS -o /dev/null http://127.0.0.1/ 2>/dev/null; then
    nohup python3 -m http.server 80 --directory /var/www/html >/var/log/web.log 2>&1 &
    sleep 1
fi

cat > /var/www/html/.env <<EOF
SSH_USER=${BOX_LEAK_USER}
SSH_PASS=${BOX_LEAK_PASS}
EOF
