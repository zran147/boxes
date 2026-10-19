set -eu
mkdir -p /srv/heartbleed
printf 'heartbleed-vulnerable-openssl\n' > /srv/heartbleed/index.html
pkill -f 'http.server 8442' 2>/dev/null || true
nohup python3 -m http.server 8442 --directory /srv/heartbleed >/var/log/heartbleed-banner.log 2>&1 &
sleep 1
