#!/bin/sh
# Stand up FTP as required, then plant the leaked SSH credentials in the share.
set -eu
if ! command -v vsftpd >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq vsftpd
fi
u="${BOX_U:?BOX_U is not set}"
p="${BOX_P-}"

mkdir -p /srv/ftp /var/run/vsftpd/empty
chmod -R 755 /srv/ftp

if [ "$u" = "anonymous" ]; then
    anon=YES
else
    anon=NO
    id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
    usermod -s /bin/bash "$u" 2>/dev/null || true
    echo "$u:$p" | chpasswd
fi

cat > /etc/vsftpd.conf <<EOF
listen=YES
listen_ipv6=NO
anonymous_enable=$anon
local_enable=YES
write_enable=NO
local_root=/srv/ftp
anon_root=/srv/ftp
pasv_enable=YES
pasv_min_port=30000
pasv_max_port=30010
secure_chroot_dir=/var/run/vsftpd/empty
seccomp_sandbox=NO
check_shell=NO
EOF

mkdir -p /srv/ftp/backup
cat > /srv/ftp/backup/.env <<EOF
SSH_USER=${BOX_SSH_USER}
SSH_PASS=${BOX_SSH_PASS}
EOF
chmod -R 755 /srv/ftp

pkill -x vsftpd 2>/dev/null || true
nohup vsftpd /etc/vsftpd.conf >/var/log/vsftpd.log 2>&1 &
sleep 1
