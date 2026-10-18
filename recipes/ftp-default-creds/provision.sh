#!/bin/sh
# Stand up FTP with the selected "common" credential pair.
set -eu
if ! command -v vsftpd >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq vsftpd
fi
u="${BOX_FTP_USER:?BOX_FTP_USER is not set}"
p="${BOX_FTP_PASS-}"

mkdir -p /srv/ftp /var/run/vsftpd/empty
printf 'public readme\n' > /srv/ftp/README.txt
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

pkill -x vsftpd 2>/dev/null || true
nohup vsftpd /etc/vsftpd.conf >/var/log/vsftpd.log 2>&1 &
sleep 1
