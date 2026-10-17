# Package proxy / cache for provisioning.
#
# The targets never get direct internet. They reach this on the shared
# `br-provision` bridge (VM) or the `boxes-provision` Docker network (container),
# and this container is the only thing with egress.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        apt-cacher-ng \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/cache/apt-cacher-ng \
 && chown -R apt-cacher-ng:apt-cacher-ng /var/cache/apt-cacher-ng

EXPOSE 3142

CMD ["/usr/sbin/apt-cacher-ng", "-c", "/etc/apt-cacher-ng", "Foreground=yes"]
