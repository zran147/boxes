#!/bin/sh
# Serve a .env file leaking the credentials the next step will reuse.
set -eu
u="${BOX_LEAK_USER:?BOX_LEAK_USER is not set}"
p="${BOX_LEAK_PASS:?BOX_LEAK_PASS is not set}"

mkdir -p /srv/www
cat > /srv/www/.env <<EOF
SSH_USER=$u
SSH_PASS=$p
EOF

pkill -f 'http.server 80' 2>/dev/null || true
nohup python3 -m http.server 80 --bind 0.0.0.0 --directory /srv/www \
    >/var/log/boxes-web.log 2>&1 &
sleep 1
