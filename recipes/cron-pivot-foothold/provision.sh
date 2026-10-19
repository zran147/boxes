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

id guly >/dev/null 2>&1 || useradd -m -s /bin/bash guly
mkdir -p /home/guly
printf 'FLAG{user-guly}\n' > /home/guly/user.txt
chown guly:guly /home/guly/user.txt
chmod 0644 /home/guly/user.txt
cat > /home/guly/pivot.sh <<'EOF'
#!/bin/sh
echo idle
EOF
chmod 0777 /home/guly /home/guly/pivot.sh
pkill -f 'guly-pivot-loop' 2>/dev/null || true
nohup su -s /bin/sh guly -c 'while true; do sh /home/guly/pivot.sh >/dev/null 2>&1; sleep 1; done' >/var/log/guly-pivot.log 2>&1 &
sleep 1
