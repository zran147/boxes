set -eu
id redis >/dev/null 2>&1 || useradd -m -s /bin/bash redis
mkdir -p /run/sshd
ssh-keygen -A >/dev/null 2>&1 || true
if ! pgrep -x sshd >/dev/null 2>&1; then /usr/sbin/sshd; fi
pkill -f 'redis_key.py 6379' 2>/dev/null || true
nohup su -s /bin/sh redis -c "exec python3 '$BOX_ASSETS/redis_key.py' 6379" >/var/log/redis.log 2>&1 &
sleep 1
