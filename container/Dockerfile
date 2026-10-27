# Dev container with an SSH-enabled sshd, tuned for JetBrains Gateway.
# Publish: docker run -d -p 127.0.0.1:2222:22 cfssh-dev
# Test on the server first: ssh -p 2222 dev@localhost

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server sudo ca-certificates curl tar gzip procps \
        git build-essential && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash dev && \
    echo "dev:changeme" | chpasswd

# --- sshd configuration: survives rebuilds; key-only login comes later ---
RUN mkdir -p /var/run/sshd /etc/ssh/sshd_config.d && \
    printf 'PasswordAuthentication yes\nPermitRootLogin no\nAllowTcpForwarding yes\n' \
        > /etc/ssh/sshd_config.d/50-dev.conf

# Host keys persist across container restarts (mount a volume on /etc/ssh).
EXPOSE 22

# Simple startup: restart sshd in the foreground.
CMD ["/usr/sbin/sshd", "-D"]
