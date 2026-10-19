u="${BOX_U:?BOX_U is not set}"
grep -q "^$u:" /etc/passwd 2>/dev/null || useradd -m -s /bin/bash "$u"
home=$(getent passwd "$u" | cut -d: -f6)
[ -n "$home" ] || home="/home/$u"
mkdir -p "/home/$u" "$home"
for d in "/home/$u" "$home"; do
    printf 'FLAG{user-%s}\n' "$u" > "$d/user.txt"
    chown "$u:$u" "$d/user.txt"
    chmod 0640 "$d/user.txt"
done

id kibana >/dev/null 2>&1 || useradd -m -s /bin/bash kibana
cat > /tmp/kibana.js <<'EOF'
// placeholder
EOF
pkill -f 'server.py command 5601' 2>/dev/null || true
nohup su -s /bin/sh kibana -c "BOX_PATH='kibana' exec python3 '$BOX_ASSETS/server.py' command 5601" >/var/log/kibana.log 2>&1 &
sleep 1
