FROM busybox:1.37.0

COPY target/x86_64-unknown-linux-musl/release/simple-idm-token-proxy /usr/local/bin/simple-idm-token-proxy

USER 1001
EXPOSE 9999

ENTRYPOINT ["/usr/local/bin/simple-idm-token-proxy"]
