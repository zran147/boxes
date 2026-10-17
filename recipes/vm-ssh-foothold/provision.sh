#!/bin/sh
# Create an SSH account on the VM and place the user flag.
set -eu
u="${BOX_U:?BOX_U is not set}"
p="${BOX_P:?BOX_P is not set}"

id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
usermod -s /bin/bash "$u"
echo "$u:$p" | chpasswd

# cloud-init disables password auth in the base image
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
grep -q '^PasswordAuthentication yes' /etc/ssh/sshd_config \
    || echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
systemctl restart ssh

home=$(getent passwd "$u" | cut -d: -f6)
[ -n "$home" ] || home="/home/$u"
mkdir -p "$home"
chown "$u:$u" "$home"
printf 'FLAG{user-%s}\n' "$u" > "$home/user.txt"
chown "$u:$u" "$home/user.txt"
chmod 0640 "$home/user.txt"
