set -eu
u="${BOX_U:?BOX_U is not set}"
p="${BOX_P:?BOX_P is not set}"
id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
echo "$u:$p" | chpasswd
pkill -f 'server.py command_auth 8098' 2>/dev/null || true
nohup su -s /bin/sh "$u" -c "BOX_PATH='${BOX_PATH:-joomla}' BOX_U='$u' BOX_P='$p' exec python3 '$BOX_ASSETS/server.py' command_auth 8098" >/var/log/web-auth.log 2>&1 &
sleep 1
