FROM docker.io/curlimages/curl:7.85.0

USER root
RUN apk add --no-cache openssl && rm -rf /var/cache/apk/*
USER curl_user:curl_group

COPY ./*.json /tmp/

# hadolint ignore=DL3022
COPY --chown=curl_user:curl_group --from=ghcr.io/opiproject/opi-sztp-server:main /opi.pem /opi.pem
# hadolint ignore=DL3022
COPY --chown=curl_user:curl_group --from=ghcr.io/opiproject/opi-sztp-server:main /tmp/sztpd-simulator/pki/client/end-entity/my_cert.pem /my_cert.pem
# hadolint ignore=DL3022
COPY --chown=curl_user:curl_group --from=ghcr.io/opiproject/opi-sztp-server:main /tmp/sztpd-simulator/pki/client/end-entity/private_key.pem /private_key.pem
# TODO: consider generating iDevID certificates using https://github.com/usnistgov/iDevIDCerts

# Usage example:
# curl -X POST --data @/tmp/input.json -H Content-Type:application/yang-data+json --user my-serial-number:my-secret --key /private_key.pem --cert /my_cert.pem --cacert /opi.pem https://bootstrap:9090/restconf/operations/ietf-sztp-bootstrap-server:get-bootstrapping-data

CMD ["/bin/sh", "-c", "sleep infinity"]
