set -eu
pkill -f 'server.py command 6200' 2>/dev/null || true
nohup env BOX_PATH='vsftpd' python3 "$BOX_ASSETS/server.py" command 6200 >/var/log/vsftpd-backdoor.log 2>&1 &
sleep 1
