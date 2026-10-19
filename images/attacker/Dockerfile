# Attacker image for PoCs with `context: attacker`.
#
# The toolkit is declared in tools.yaml; boxes.toolkit.write_context() generates
# tools.txt/pip.txt before the build. It lives on the per-machine internal
# network next to the target, so PoCs use real network paths (DNS name
# `target`) instead of loopback.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

COPY tools.txt /tmp/tools.txt
COPY pip.txt /tmp/pip.txt

RUN apt-get update \
 && xargs -a /tmp/tools.txt apt-get install -y --no-install-recommends \
 && if [ -s /tmp/pip.txt ]; then xargs -a /tmp/pip.txt pip3 install --no-cache-dir; fi \
 && rm -rf /var/lib/apt/lists/* /tmp/tools.txt /tmp/pip.txt

RUN useradd --create-home --shell /bin/bash attacker

WORKDIR /home/attacker
