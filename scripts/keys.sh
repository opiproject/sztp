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

# TODO: start using https://github.com/usnistgov/iDevIDCerts to generate all keys and certificates

# extract PEM files from the running docker image
docker-compose cp bootstrap:/opi.pem /tmp/opi.pem
docker-compose cp bootstrap:/tmp/sztpd-simulator/pki/client/end-entity/my_cert.pem /tmp/opi_cert.pem
docker-compose cp bootstrap:/tmp/sztpd-simulator/pki/client/end-entity/private_key.pem /tmp/opi_private_key.pem

# you can scp them into DPU now...
echo ==================================
echo You can now SCP pem files to the real DPU
echo sshpass -p dpupass ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 /tmp/opi*.pem dpuser@[dpu-ip]:~
echo ==================================

echo "DONE"
