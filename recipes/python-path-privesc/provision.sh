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

mkdir -p /opt/admirer
cat > /opt/admirer/backup.py <<'EOF'
import shutil
EOF
chmod 0777 /opt/admirer
cat > /opt/admirer/importme.py <<'EOF'
open('/tmp/admirer-root', 'w').write(open('/root/root.txt').read())
EOF
chmod 0666 /opt/admirer/importme.py
pkill -f 'admirer-loop' 2>/dev/null || true
nohup sh -c 'while true; do cd /opt/admirer && python3 -c "import importme" >/dev/null 2>&1; sleep 1; done' >/var/log/admirer-loop.log 2>&1 &
sleep 1
