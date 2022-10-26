FROM docker.io/library/python:3.10.8-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
# hadolint ignore=DL3022
COPY --from=ghcr.io/opiproject/opi-sztp-server:main /tmp/my-boot-image.img /var/lib/misc/my-boot-image.img
CMD [ "python3", "-m", "http.server", "8082"]
HEALTHCHECK CMD curl --fail http://localhost:8082 || exit 1
