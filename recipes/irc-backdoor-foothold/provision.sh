set -eu
id ircd >/dev/null 2>&1 || useradd -m -s /bin/bash ircd
pkill -f 'server.py command 8067' 2>/dev/null || true
nohup su -s /bin/sh ircd -c "BOX_PATH='' exec python3 '$BOX_ASSETS/server.py' command 8067" >/var/log/ircd.log 2>&1 &
sleep 1
