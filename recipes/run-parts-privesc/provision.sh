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

mkdir -p /usr/local/bin
cat > /usr/local/bin/run-parts <<'EOF'
#!/bin/sh
cat /root/root.txt > /tmp/runparts-root
EOF
chmod 0777 /usr/local/bin/run-parts
pkill -f 'runparts-loop' 2>/dev/null || true
nohup sh -c 'while true; do /usr/local/bin/run-parts >/dev/null 2>&1; sleep 1; done' >/var/log/runparts-loop.log 2>&1 &
sleep 1
