set -eu
id kid >/dev/null 2>&1 || useradd -m -s /bin/bash kid
home=$(getent passwd kid | cut -d: -f6); [ -n "$home" ] || home=/home/kid
printf 'FLAG{user-kid}\n' > /home/kid/user.txt
chown kid:kid /home/kid/user.txt
chmod 0640 /home/kid/user.txt
pkill -f 'server.py command 8094' 2>/dev/null || true
nohup su -s /bin/sh kid -c "BOX_PATH='sk' exec python3 '$BOX_ASSETS/server.py' command 8094" >/var/log/msfvenom.log 2>&1 &
sleep 1
