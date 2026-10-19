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

mkdir -p /opt/server_admin
cat > /opt/server_admin/reporter.py <<'EOF'
import reporter
EOF
chmod 0666 /opt/server_admin/reporter.py
cat > /opt/server_admin/reporter.py <<'EOF'
#!/usr/bin/env python3
open('/tmp/libhijack-root', 'w').write(open('/root/root.txt').read())
EOF
chmod 0777 /opt/server_admin
pkill -f 'python3 /opt/server_admin/reporter.py' 2>/dev/null || true
nohup sh -c 'while true; do python3 /opt/server_admin/reporter.py >/dev/null 2>&1; sleep 1; done' >/var/log/python-hijack.log 2>&1 &
sleep 1
