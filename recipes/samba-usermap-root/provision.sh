printf 'FLAG{root-%s}\n' "${BOX_U:-root}" > /root/root.txt
chmod 0600 /root/root.txt

pkill -f 'server.py command 8446' 2>/dev/null || true
nohup env BOX_PATH='' python3 "$BOX_ASSETS/server.py" command 8446 >/var/log/samba-root.log 2>&1 &
sleep 1
