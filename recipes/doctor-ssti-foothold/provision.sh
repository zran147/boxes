set -eu
id web >/dev/null 2>&1 || useradd -m -s /bin/bash web
pkill -f 'server.py command 8092' 2>/dev/null || true
nohup su -s /bin/sh web -c "BOX_PATH='doctor' exec python3 '$BOX_ASSETS/server.py' command 8092" >/var/log/doctor-ssti.log 2>&1 &
sleep 1
