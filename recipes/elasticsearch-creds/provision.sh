set -eu
mkdir -p /srv/es
printf '{"user":"%s","pass":"%s"}\n' "${BOX_U:-security}" "${BOX_P:-spanish.is.key}" > /srv/es/creds.json
pkill -f 'http.server 9200' 2>/dev/null || true
nohup python3 -m http.server 9200 --directory /srv/es >/var/log/elastic.log 2>&1 &
sleep 1
