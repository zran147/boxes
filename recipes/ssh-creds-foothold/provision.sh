#!/bin/sh
# Create the account and start sshd, then place the user flag.
# This runs on both the container proxy and the VM product.
set -eu
u="${BOX_U:?BOX_U is not set}"
p="${BOX_P:?BOX_P is not set}"

id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
usermod -s /bin/bash "$u"
echo "$u:$p" | chpasswd

# cloud-init (VM) writes PasswordAuthentication no into sshd_config.d; that
# drop-in is included first and wins over the main config.
mkdir -p /etc/ssh/sshd_config.d /run/sshd
for f in /etc/ssh/sshd_config.d/*.conf; do
    [ -e "$f" ] || continue
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' "$f"
done
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
if ! grep -Rqs '^PasswordAuthentication yes' /etc/ssh/sshd_config.d/ 2>/dev/null; then
    echo 'PasswordAuthentication yes' > /etc/ssh/sshd_config.d/99-boxes.conf
fi
ssh-keygen -A >/dev/null 2>&1 || true

started=0
if command -v systemctl >/dev/null 2>&1; then
    if systemctl restart ssh 2>/dev/null; then
        started=1
    fi
fi
if [ "$started" -eq 0 ]; then
    pkill -x sshd 2>/dev/null || true
    /usr/sbin/sshd
fi

sshd -T 2>/dev/null | grep -q '^passwordauthentication yes' \
    || { echo "password authentication is still disabled" >&2; exit 1; }

home=$(getent passwd "$u" | cut -d: -f6)
[ -n "$home" ] || home="/home/$u"
mkdir -p "$home"
chown "$u:$u" "$home"
printf 'FLAG{user-%s}\n' "$u" > "$home/user.txt"
chown "$u:$u" "$home/user.txt"
chmod 0640 "$home/user.txt"
