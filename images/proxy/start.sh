#!/bin/sh
set -eu

mkdir -p /srv/artifacts
/usr/sbin/apt-cacher-ng -c /etc/apt-cacher-ng ForeGround=1 \
    >/var/log/apt-cacher.log 2>&1 &

rm -f /run/squid.pid

python3 -m http.server 8000 --bind 0.0.0.0 --directory /srv/artifacts \
    >/var/log/artifacts.log 2>&1 &

exec squid -N -f /etc/squid/squid.conf
