u="${BOX_U:?BOX_U is not set}"
grep -q "^$u:" /etc/passwd 2>/dev/null || useradd -m -s /bin/bash "$u"
home=$(getent passwd "$u" | cut -d: -f6)
[ -n "$home" ] || home="/home/$u"
mkdir -p "/home/$u" "$home"
for d in "/home/$u" "$home"; do
    printf 'FLAG{user-%s}\n' "$u" > "$d/user.txt"
    chown "$u:$u" "$d/user.txt"
    chmod 0640 "$d/user.txt"
done

id joanna >/dev/null 2>&1 || useradd -m -s /bin/bash joanna
home=$(getent passwd joanna | cut -d: -f6); [ -n "$home" ] || home=/home/joanna
printf 'FLAG{user-joanna}\n' > /home/joanna/user.txt
chown joanna:joanna /home/joanna/user.txt
chmod 0640 /home/joanna/user.txt
pkill -f 'server.py command 52846' 2>/dev/null || true
nohup su -s /bin/sh joanna -c "BOX_PATH='internal' exec python3 '$BOX_ASSETS/server.py' command 52846" >/var/log/internal-site.log 2>&1 &
sleep 1
