#!/bin/sh
# Make this recipe's precondition real: a SUID copy of find.
set -eu
u="${BOX_U:?BOX_U is not set}"
bin="${BOX_BINARY:?BOX_BINARY is not set}"
case "$bin" in
    *[!a-zA-Z0-9_-]*) echo "unsafe binary name: $bin" >&2; exit 1 ;;
esac
id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
cp /usr/bin/find "/usr/local/bin/$bin"
chown root:root "/usr/local/bin/$bin"
chmod 4755 "/usr/local/bin/$bin"
