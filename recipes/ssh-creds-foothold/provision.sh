#!/bin/sh
# Create the account and start sshd, then place the user flag.
set -eu
u="${BOX_U:?BOX_U is not set}"
p="${BOX_P:?BOX_P is not set}"

id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
echo "$u:$p" | chpasswd

mkdir -p /run/sshd
ssh-keygen -A >/dev/null 2>&1 || true
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
grep -q '^PasswordAuthentication yes' /etc/ssh/sshd_config \
    || echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config

pkill -x sshd 2>/dev/null || true
/usr/sbin/sshd

printf 'FLAG{user-%s}\n' "$u" > "/home/$u/user.txt"
chown "$u:$u" "/home/$u/user.txt"
chmod 0640 "/home/$u/user.txt"
