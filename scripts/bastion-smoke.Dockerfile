FROM alpine:3.22
RUN apk add --no-cache openssh-server \
    && adduser -D -s /bin/sh fixture \
    && passwd -u fixture \
    && mkdir -p /run/sshd
# The harness mounts only this disposable target's configuration and public CA.
# The CA private key, JWT key and signer credentials never enter this image.
ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e", "-f", "/fixture/sshd_config"]
