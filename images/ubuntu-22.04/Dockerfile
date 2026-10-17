# Base image for the container fast path.
#
# Built once with network access; every machine container is then created from
# this tag with `--network none`, so recipe provisioning and PoCs never need
# egress. Keep this lean: only tooling that recipes legitimately rely on.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        sudo \
        findutils \
        python3 \
        curl \
        ca-certificates \
        procps \
        iproute2 \
        less \
 && rm -rf /var/lib/apt/lists/*

# An unprivileged "attacker" principal that network-facing PoCs run as.
RUN useradd --create-home --shell /bin/bash attacker \
 && echo 'attacker:attacker' | chpasswd

WORKDIR /root
