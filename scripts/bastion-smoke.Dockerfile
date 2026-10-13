FROM alpine:3.22
RUN apk add --no-cache openssh-server openssh-sftp-server sudo \
    && adduser -D -s /bin/sh fixture \
    && passwd -u fixture \
    && mkdir -p /run/sshd /etc/sudoers.d \
    && printf 'fixture ALL=(root) NOPASSWD: /usr/lib/ssh/sftp-server -R\n' > /etc/sudoers.d/fixture-sftp \
    && chmod 0440 /etc/sudoers.d/fixture-sftp \
    && printf 'root-only-fixture\n' > /root/bastion-proof.txt \
    && chmod 0600 /root/bastion-proof.txt
# The harness mounts only this disposable target's configuration and public CA.
# The CA private key, JWT key and signer credentials never enter this image.
ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e", "-f", "/fixture/sshd_config"]
