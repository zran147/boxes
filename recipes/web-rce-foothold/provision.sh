#!/bin/sh
# Build the vulnerable web app and the user flag it exposes.
set -eu
u="${BOX_WEB_USER:?BOX_WEB_USER is not set}"
id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
mkdir -p "/home/$u"
printf 'FLAG{user-%s}\n' "$u" > "/home/$u/user.txt"
chown "$u:$u" "/home/$u/user.txt"
chmod 0640 "/home/$u/user.txt"

mkdir -p /opt/app
cp "$BOX_ASSETS/server.py" /opt/app/server.py
chmod 0644 /opt/app/server.py

nohup su -s /bin/sh "$u" -c 'exec python3 /opt/app/server.py' >/var/log/app.log 2>&1 &
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS http://127.0.0.1:8080/ >/dev/null 2>&1; then
        exit 0
    fi
    sleep 0.5
done
echo "web app failed to start" >&2
cat /var/log/app.log >&2 || true
exit 1
