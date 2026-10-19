set -eu
mkdir -p /srv/adminer
printf 'ADMINER_USER=%s\nADMINER_PASS=%s\n' "${BOX_U:-waldo}" "${BOX_P:-password}" > /srv/adminer/config.php
pkill -f 'http.server 8091' 2>/dev/null || true
nohup python3 -m http.server 8091 --directory /srv/adminer >/var/log/adminer.log 2>&1 &
sleep 1
