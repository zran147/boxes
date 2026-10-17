#!/bin/sh
# Provisioning smoke test: install through the package proxy.
set -eu
export DEBIAN_FRONTEND=noninteractive
id attacker >/dev/null 2>&1 || useradd -m -s /bin/bash attacker
apt-get update -qq
apt-get install -y -qq sl
