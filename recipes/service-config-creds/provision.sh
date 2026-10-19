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

mkdir -p /var/www/conf
printf 'db_user=%s\ndb_pass=%s\n' "${BOX_DB_USER:-jimmy}" "${BOX_DB_PASS:-password}" > /var/www/conf/database.conf
chmod 0644 /var/www/conf/database.conf
