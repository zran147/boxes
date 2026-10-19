set -eu
id pi >/dev/null 2>&1 || useradd -m -s /bin/bash pi
echo 'pi:raspberry' | chpasswd
mkdir -p /etc/ssh/sshd_config.d /run/sshd
for f in /etc/ssh/sshd_config.d/*.conf; do
    [ -e "$f" ] || continue
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' "$f"
done
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
grep -Rqs '^PasswordAuthentication yes' /etc/ssh/sshd_config.d/ 2>/dev/null \
    || echo 'PasswordAuthentication yes' > /etc/ssh/sshd_config.d/99-boxes.conf
ssh-keygen -A >/dev/null 2>&1 || true
if ! pgrep -x sshd >/dev/null 2>&1; then
    /usr/sbin/sshd
fi
