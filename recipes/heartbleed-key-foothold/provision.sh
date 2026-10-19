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
mkdir -p "$home/.ssh" /opt/boxes/leak
[ -f /opt/boxes/leak/hype_key ] || ssh-keygen -q -t rsa -b 2048 -N '' -f /opt/boxes/leak/hype_key
cp /opt/boxes/leak/hype_key.pub "$home/.ssh/authorized_keys"
chown -R "$u:$u" "$home/.ssh"
chmod 0700 "$home/.ssh"
chmod 0600 "$home/.ssh/authorized_keys"
mkdir -p /run/sshd
ssh-keygen -A >/dev/null 2>&1 || true
if ! pgrep -x sshd >/dev/null 2>&1; then /usr/sbin/sshd; fi
chmod 0644 /opt/boxes/leak/hype_key
pkill -f 'http.server 8443' 2>/dev/null || true
nohup python3 -m http.server 8443 --directory /opt/boxes/leak >/var/log/heartbleed-key.log 2>&1 &
sleep 1
