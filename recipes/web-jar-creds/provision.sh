set -eu
u="${BOX_U:?BOX_U is not set}"
p="${BOX_P:?BOX_P is not set}"
path="${BOX_PATH:?BOX_PATH is not set}"
path="${path#/}"; path="${path%/}"
mkdir -p "/srv/jar/$path"
printf 'DB_USER=%s\nDB_PASS=%s\n' "$u" "$p" > /srv/jar/creds.txt
(cd /srv/jar && python3 -m zipfile -c "/srv/jar/$path/BlockCore.jar" creds.txt)
rm -f /srv/jar/creds.txt
pkill -f 'http.server 8086' 2>/dev/null || true
nohup python3 -m http.server 8086 --directory /srv/jar >/var/log/blocky-jar.log 2>&1 &
sleep 1
