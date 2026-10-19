set -eu
u="${BOX_U:?BOX_U is not set}"
p="${BOX_P:?BOX_P is not set}"
mkdir -p /opt/boxes
printf 'SSH_USER=%s\nSSH_PASS=%s\n' "$u" "$p" > /opt/boxes/elastix.conf
pkill -f 'server.py lfi 8081' 2>/dev/null || true
nohup env BOX_PATH="${BOX_PATH:-vtigercrm}" python3 "$BOX_ASSETS/server.py" lfi 8081 >/var/log/elastix-lfi.log 2>&1 &
sleep 1
