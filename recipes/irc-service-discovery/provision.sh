set -eu
mkdir -p /srv/irc
printf 'UnrealIRCd 3.2.8.1\n' > /srv/irc/index.html
pkill -f 'http.server 8066' 2>/dev/null || true
nohup python3 -m http.server 8066 --directory /srv/irc >/var/log/irc-banner.log 2>&1 &
sleep 1
