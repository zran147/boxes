#!/bin/sh
# Provisioning smoke test: install through the package proxy.
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq sl
