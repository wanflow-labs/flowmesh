# SPDX-License-Identifier: Apache-2.0
# A Debian container with systemd as PID 1, for testing packaging/systemd/flowmeshd.service under the
# real sandboxing options. Same base as the dev image (bookworm), so binaries built in fm1 run here.
FROM debian:bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv iproute2 iputils-ping dbus procps \
 && rm -rf /var/lib/apt/lists/* \
 && systemctl mask getty@tty1.service systemd-logind.service console-getty.service
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
