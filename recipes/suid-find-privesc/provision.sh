#!/bin/sh
# Leave a SUID-root find binary and the root flag.
set -eu
u="${BOX_U:?BOX_U is not set}"
id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"

chown root:root /usr/bin/find
chmod 4755 /usr/bin/find

echo "FLAG{root-$u}" > /root/root.txt
chmod 0600 /root/root.txt
