#!/bin/sh
# Create an SSH account on the VM and place the user flag.
set -eu
u="${BOX_U:?BOX_U is not set}"
p="${BOX_P:?BOX_P is not set}"

id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
usermod -s /bin/bash "$u"
echo "$u:$p" | chpasswd

# cloud-init writes PasswordAuthentication no into sshd_config.d; that drop-in
# is included first and wins over the main config. Fix every drop-in as well.
for f in /etc/ssh/sshd_config.d/*.conf; do
    [ -e "$f" ] || continue
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' "$f"
done
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
if ! grep -Rqs '^PasswordAuthentication yes' /etc/ssh/sshd_config.d/ 2>/dev/null; then
    echo 'PasswordAuthentication yes' > /etc/ssh/sshd_config.d/99-boxes.conf
fi
systemctl restart ssh
sshd -T 2>/dev/null | grep -q '^passwordauthentication yes' \
    || { echo "password authentication is still disabled" >&2; exit 1; }

home=$(getent passwd "$u" | cut -d: -f6)
[ -n "$home" ] || home="/home/$u"
mkdir -p "$home"
chown "$u:$u" "$home"
printf 'FLAG{user-%s}\n' "$u" > "$home/user.txt"
chown "$u:$u" "$home/user.txt"
chmod 0640 "$home/user.txt"
