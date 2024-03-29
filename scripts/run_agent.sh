#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2022 Dell Inc, or its subsidiaries.

set -euxo pipefail

# check you on right architecture
uname -a

# check what you have curently
docker images
docker ps
DOCKER_SZTP_IMAGE=opi-sztp-agen-client:latest

# assume keys are in /mnt
ls -l /mnt/

# run docker (not compose) in host network
DHCLIENT_LEASE_FILE=/var/lib/NetworkManager/dhclient-eth0.lease
docker run --rm -it --network=host -v /mnt/:/mnt \
    --mount type=bind,source=${DHCLIENT_LEASE_FILE},target=/var/lib/dhclient/dhclient.leases \
    ${DOCKER_SZTP_IMAGE} \
    /opi-sztp-agent daemon --bootstrap-trust-anchor-cert /mnt/opi.pem --device-end-entity-cert /mnt/opi_cert.pem --device-private-key /mnt/opi_private_key.pem

echo "DONE"
