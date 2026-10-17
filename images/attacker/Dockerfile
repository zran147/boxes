# Attacker image for PoCs with `context: attacker`.
#
# It lives on the per-machine internal network next to the target, so PoCs use
# real network paths (DNS name `target`) instead of loopback. Grow the toolkit
# as recipes need it; keep it pinned and rebuildable.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        openssh-client \
        sshpass \
        python3 \
        python3-pip \
        nmap \
        netcat-openbsd \
        socat \
        dnsutils \
        iproute2 \
        jq \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash attacker

WORKDIR /home/attacker
