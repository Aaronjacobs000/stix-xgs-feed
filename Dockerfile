# stix-xgs-feed serve mode in a container. Standard library only, no pip install.
# Build: docker build -t stix-xgs-feed .
# Run:   see compose.yaml and the README section "Docker".
ARG PYTHON_IMAGE=python:3.13-slim-trixie
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

RUN groupadd --system --gid 10001 feed \
 && useradd --system --uid 10001 --gid feed --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin feed \
 && mkdir -p /data /config \
 && chown feed:feed /data

WORKDIR /app
COPY LICENSE README.md allowlist.example.txt /app/
COPY stix_xgs_feed/ /app/stix_xgs_feed/

USER 10001:10001
VOLUME ["/data"]
EXPOSE 8443

# /healthz answers 200 once the first refresh has written the three files.
HEALTHCHECK --interval=60s --timeout=10s --start-period=60s --retries=3 \
  CMD ["python", "-m", "stix_xgs_feed", "healthcheck", "--config", "/config/feed.toml"]

ENTRYPOINT ["python", "-m", "stix_xgs_feed"]
CMD ["serve", "--config", "/config/feed.toml"]
