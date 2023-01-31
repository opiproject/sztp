# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2022 Dell Inc, or its subsidiaries.

FROM docker.io/library/python:3.10.8-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# hadolint ignore=DL3022
COPY --from=ghcr.io/opiproject/opi-sztp-server:main /opi.pem /opi.pem
# hadolint ignore=DL3022
COPY --from=ghcr.io/opiproject/opi-sztp-server:main /tmp/sztpd-simulator/pki/sztpd1/sbi/end-entity/my_cert.pem /my_cert.pem
# hadolint ignore=DL3022
COPY --from=ghcr.io/opiproject/opi-sztp-server:main /tmp/sztpd-simulator/pki/sztpd1/sbi/end-entity/private_key.pem /private_key.pem

# COPY --from=ghcr.io/opiproject/opi-sztp-server:main /tmp/sztpd-simulator/pki/client/end-entity/private_key.pem /client_key.pem
# COPY --from=ghcr.io/opiproject/opi-sztp-server:main /tmp/sztpd-simulator/pki/client/end-entity/my_cert.pem /client_cert.pem

# hadolint ignore=DL3022
COPY --from=ghcr.io/opiproject/opi-sztp-server:main /tmp/my-boot-image.img /var/lib/misc/my-boot-image.img
COPY ./https-simple-server.py /opt/
CMD ["python3", "/opt/https-simple-server.py"]
HEALTHCHECK CMD curl --fail --key /private_key.pem --cert /my_cert.pem --cacert /opi.pem https://localhost:443 || exit 1
