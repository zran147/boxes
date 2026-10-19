set -eu
id www-data >/dev/null 2>&1 || useradd -m -s /bin/bash www-data
pkill -f 'server.py command 8093' 2>/dev/null || true
nohup su -s /bin/sh www-data -c "BOX_PATH='laravel' exec python3 '$BOX_ASSETS/server.py' command 8093" >/var/log/laravel.log 2>&1 &
sleep 1
