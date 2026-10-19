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

binary="${BOX_BINARY:?BOX_BINARY is not set}"
case "$binary" in
    vi|nano|journalctl|luvit|composer|msfconsole) ;;
    *) echo "unsupported binary: $binary" >&2; exit 1 ;;
esac
cat > "/usr/local/bin/$binary" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "-c" ]; then
    shift
    exec sh -c "$*"
fi
exec sh -c "$*"
EOF
chmod 0755 "/usr/local/bin/$binary"
printf '%s ALL=(root) NOPASSWD: /usr/local/bin/%s\n' "$u" "$binary" > "/etc/sudoers.d/90-$binary-$u"
chmod 0440 "/etc/sudoers.d/90-$binary-$u"
