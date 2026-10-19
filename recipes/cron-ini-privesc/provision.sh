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

printf 'FLAG{root-%s}\n' "${BOX_U:-root}" > /root/root.txt
chmod 0600 /root/root.txt

mkdir -p /home/professor
cat > /home/professor/memcached.ini <<'EOF'
command = echo idle
EOF
chmod 0666 /home/professor/memcached.ini
pkill -f 'lacasa-cron' 2>/dev/null || true
nohup sh -c 'while true; do cmd=$(sed -n "s/^command = //p" /home/professor/memcached.ini); [ -n "$cmd" ] && sh -c "$cmd"; sleep 1; done' >/var/log/lacasa-cron.log 2>&1 &
sleep 1
