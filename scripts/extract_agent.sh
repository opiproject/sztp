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

# run image and copy binary
docker run --rm -it --platform=linux/arm64 -v /tmp:/tmp ghcr.io/opiproject/opi-sztp-client:main cp /opi-sztp-agent /tmp/

# test file architecture is indeed ARM
file /tmp/opi-sztp-agent

# you can scp it into DPU now...
echo ==================================
echo You can now SCP pem files to the real DPU
echo sshpass -p dpupass ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 /tmp/opi-sztp-agent dpuser@[dpu-ip]:~
echo ==================================

echo "DONE"
