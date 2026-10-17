#!/bin/sh
# Make this recipe's precondition real: a shell as $BOX_U.
set -eu
u="${BOX_U:?BOX_U is not set}"
bin="${BOX_BINARY:?BOX_BINARY is not set}"
case "$u" in
    *[!a-zA-Z0-9_-]*) echo "unsafe username: $u" >&2; exit 1 ;;
esac
id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"

printf '%s ALL=(root) NOPASSWD: %s\n' "$u" "$bin" > "/etc/sudoers.d/90-$u"
chmod 0440 "/etc/sudoers.d/90-$u"

echo "FLAG{root-$u}" > /root/root.txt
chmod 0600 /root/root.txt
