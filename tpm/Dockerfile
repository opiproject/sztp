FROM debian:12.6-slim

RUN apt-get update && \
    apt-get install --no-install-recommends -y swtpm=0.7.1-1.3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/usr/bin/swtpm"]
