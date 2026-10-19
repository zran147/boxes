set -eu
u="${BOX_U:?BOX_U is not set}"
id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
home=$(getent passwd "$u" | cut -d: -f6)
[ -n "$home" ] || home="/home/$u"
mkdir -p "/home/$u" "$home"
for d in "/home/$u" "$home"; do
    printf 'FLAG{user-%s}\n' "$u" > "$d/user.txt"
    chown "$u:$u" "$d/user.txt"
    chmod 0640 "$d/user.txt"
done
pkill -f 'server.py command 8084' 2>/dev/null || true
nohup su -s /bin/sh "$u" -c "BOX_PATH='${BOX_PATH:-dev}' exec python3 '$BOX_ASSETS/server.py' command 8084" >/var/log/phpbash.log 2>&1 &
sleep 1
