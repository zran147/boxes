p="${BOX_P:?BOX_P is not set}"

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

mkdir -p /var/www/html/ona/local/config
printf 'db_login=jimmy\ndb_passwd=%s\n' "$p" > /var/www/html/ona/local/config/database_settings.inc.php
chmod 0644 /var/www/html/ona/local/config/database_settings.inc.php
