FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY dist/sshmap /usr/local/bin/sshmap

WORKDIR /data
VOLUME ["/data"]

ENTRYPOINT ["sshmap"]
CMD ["--help"]
