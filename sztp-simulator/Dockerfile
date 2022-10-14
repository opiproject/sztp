FROM docker.io/library/python:3.10.8-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY ./input.json /tmp/

# hadolint ignore=DL3022
COPY --from=ghcr.io/opiproject/opi-sztp-server:main /opi.pem /opi.pem
# hadolint ignore=DL3022
COPY --from=ghcr.io/opiproject/opi-sztp-server:main /tmp/sztpd-simulator/pki/client/end-entity/my_cert.pem /my_cert.pem
# hadolint ignore=DL3022
COPY --from=ghcr.io/opiproject/opi-sztp-server:main /tmp/sztpd-simulator/pki/client/end-entity/private_key.pem /private_key.pem
# TODO: consider generating iDevID certificates using https://github.com/usnistgov/iDevIDCerts

CMD ["/bin/sh", "-c", "sleep infinity"]
