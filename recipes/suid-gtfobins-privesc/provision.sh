#!/bin/sh
# Make this recipe's precondition real: a shell as $BOX_U.
set -eu
u="${BOX_U:?BOX_U is not set}"
case "$u" in
    *[!a-zA-Z0-9_-]*) echo "unsafe username: $u" >&2; exit 1 ;;
esac
id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"

# The discovered SUID binary (a copy of find, for this slice).
bin="${BOX_BINARY:?BOX_BINARY is not set}"
case "$bin" in
    *[!a-zA-Z0-9_-]*) echo "unsafe binary name: $bin" >&2; exit 1 ;;
esac
cp /usr/bin/find "/usr/local/bin/$bin"
chown root:root "/usr/local/bin/$bin"
chmod 4755 "/usr/local/bin/$bin"

echo "FLAG{root-$u}" > /root/root.txt
chmod 0600 /root/root.txt
