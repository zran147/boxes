# Ubuntu 24.04 base for the container fast path.
FROM ubuntu:24.04

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
        vsftpd \
        openssh-server \
        openssh-client \
        sshpass \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash attacker \
 && echo 'attacker:attacker' | chpasswd

WORKDIR /root
