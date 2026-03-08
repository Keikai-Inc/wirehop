FROM ubuntu:24.04
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates jq && \
    rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash hop
COPY hop /usr/local/bin/hop
RUN chmod +x /usr/local/bin/hop
RUN mkdir -p /shared && chown hop:hop /shared
USER hop
ENTRYPOINT ["/bin/bash"]
