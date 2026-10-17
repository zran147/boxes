#!/bin/sh
# Prove the directory exists by brute-forcing a small wordlist from an
# unprivileged context.
set -eu
found=""
for w in admin backup dev secret api; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1/$w/")
    if [ "$code" = "200" ]; then
        found="$w"
        break
    fi
done
[ -n "$found" ] || { echo "no hidden directory discovered" >&2; exit 1; }
echo "discovered /$found/"
