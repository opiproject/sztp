#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2022 Dell Inc, or its subsidiaries.

set -euxo pipefail

# docker compose plugin
command -v docker-compose || { shopt -s expand_aliases && alias docker-compose='docker compose'; }

# let everything start
sleep 5

# print for debug
docker-compose ps

# test dhcp server
docker-compose cp bootstrap:/opi.pem /tmp/opi.pem
docker-compose cp bootstrap:/tmp/sztpd-simulator/pki/client/end-entity/my_cert.pem /tmp/my_cert.pem
docker-compose cp bootstrap:/tmp/sztpd-simulator/pki/client/end-entity/private_key.pem /tmp/private_key.pem

echo "DONE"
