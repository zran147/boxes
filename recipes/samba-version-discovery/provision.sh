set -eu
mkdir -p /srv/samba
printf 'Samba 3.0.20-Debian\n' > /srv/samba/index.html
pkill -f 'http.server 8444' 2>/dev/null || true
nohup python3 -m http.server 8444 --directory /srv/samba >/var/log/samba-banner.log 2>&1 &
sleep 1
