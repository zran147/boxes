set -eu
u="${BOX_U:?BOX_U is not set}"
id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
pkill -f 'server.py command 8084' 2>/dev/null || true
nohup su -s /bin/sh "$u" -c "BOX_PATH='${BOX_PATH:-dev}' exec python3 '$BOX_ASSETS/server.py' command 8084" >/var/log/web-shell.log 2>&1 &
sleep 1
