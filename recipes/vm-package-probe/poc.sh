#!/bin/sh
# Runs after the provision NIC is sealed: the package must already be installed.
set -eu
dpkg -s sl >/dev/null 2>&1 || { echo "sl was not installed" >&2; exit 1; }
echo "sl installed and still present after seal"
