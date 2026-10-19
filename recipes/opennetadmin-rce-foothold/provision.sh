set -eu
id www-data >/dev/null 2>&1 || useradd -m -s /bin/bash www-data
pkill -f 'server.py command 8090' 2>/dev/null || true
nohup su -s /bin/sh www-data -c "BOX_PATH='${BOX_PATH:-ona}' exec python3 '$BOX_ASSETS/server.py' command 8090" >/var/log/ona.log 2>&1 &
sleep 1
