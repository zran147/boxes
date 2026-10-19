set -eu
mkdir -p /srv/smb
printf 'USER=%s\nPASS=%s\n' "${BOX_U:-admin}" "${BOX_P:-password}" > /srv/smb/creds.txt
pkill -f 'http.server 8447' 2>/dev/null || true
nohup python3 -m http.server 8447 --directory /srv/smb >/var/log/smb-guest.log 2>&1 &
sleep 1
