#!/bin/sh
# Prove the common credential pair works from an unprivileged context.
set -eu
out=$(curl -sS "ftp://${BOX_FTP_USER}:${BOX_FTP_PASS}@127.0.0.1/")
echo "$out"
echo "$out" | grep -q 'README.txt' || { echo "FTP listing failed" >&2; exit 1; }
