#!/bin/sh
set -eu

mkdir -p /srv/artifacts /var/spool/squid
for d in $(seq 0 15); do mkdir -p "/var/spool/squid/$(printf '%02X' "$d")"; done
chown -R proxy:proxy /var/spool/squid
rm -f /run/squid.pid

python3 -m http.server 8000 --bind 0.0.0.0 --directory /srv/artifacts \
    >/var/log/artifacts.log 2>&1 &

exec squid -N -f /etc/squid/squid.conf
