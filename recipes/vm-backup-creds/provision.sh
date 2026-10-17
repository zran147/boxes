#!/bin/sh
# Serve a backup directory leaking credentials.
set -eu
u="${BOX_BACKUP_USER:?BOX_BACKUP_USER is not set}"
p="${BOX_BACKUP_PASS:?BOX_BACKUP_PASS is not set}"

mkdir -p /srv/backup
cat > /srv/backup/credentials.txt <<EOF
user=$u
pass=$p
EOF

pkill -f 'http.server 8080' 2>/dev/null || true
nohup python3 -m http.server 8080 --bind 0.0.0.0 --directory /srv/backup \
    >/var/log/boxes-backup.log 2>&1 &
sleep 1
