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

mkdir -p /opt/kibana
chmod 0777 /opt/kibana
pkill -f 'logstash-loop' 2>/dev/null || true
nohup sh -c 'while true; do for f in /opt/kibana/logstash_*; do [ -f "$f" ] || continue; cmd=$(sed -n "s/.*comando: //p" "$f" | head -1); [ -n "$cmd" ] && sh -c "$cmd"; rm -f "$f"; done; sleep 1; done' >/var/log/logstash-loop.log 2>&1 &
sleep 1
