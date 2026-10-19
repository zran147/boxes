set -eu
u="${BOX_U:?BOX_U is not set}"
p="${BOX_P:?BOX_P is not set}"
id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
echo "$u:$p" | chpasswd
home=$(getent passwd "$u" | cut -d: -f6)
[ -n "$home" ] || home="/home/$u"
mkdir -p "/home/$u" "$home"
for d in "/home/$u" "$home"; do
    printf 'FLAG{user-%s}\n' "$u" > "$d/user.txt"
    chown "$u:$u" "$d/user.txt"
    chmod 0640 "$d/user.txt"
done
pkill -f 'server.py upload_auth 8083' 2>/dev/null || true
nohup su -s /bin/sh "$u" -c "BOX_PATH='${BOX_PATH:-nibbleblog}' BOX_U='$u' BOX_P='$p' exec python3 '$BOX_ASSETS/server.py' upload_auth 8083" >/var/log/nibble-upload.log 2>&1 &
sleep 1
