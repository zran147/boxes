set -eu
pkill -f 'dns_zone.py 8053' 2>/dev/null || true
nohup python3 "$BOX_ASSETS/dns_zone.py" 8053 >/var/log/dns-zone.log 2>&1 &
sleep 1
