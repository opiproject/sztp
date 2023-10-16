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

# define values
BOOTSTRAP_URL=http://localhost:7080/restconf/ds/ietf-datastores:running
BOOT_IMG_PATH=my-second-boot-image.img
BOOT_IMG_HASH_VAL=`openssl dgst -sha256 -c ${BOOT_IMG_PATH} | awk '{print $2}'`

# create input json file for curl
cat << EOM > /tmp/boot-images.json
{
    "wn-sztpd-1:boot-images": {
        "boot-image": [
            {
                "name": "my-boot-image.img",
                "download-uri": [
                    "http://web:80/${BOOT_IMG_PATH}",
                    "ftp://web:82/${BOOT_IMG_PATH}"
                ],
                "image-verification": [
                    {
                        "hash-algorithm": "ietf-sztp-conveyed-info:sha-256",
                        "hash-value": "${BOOT_IMG_HASH_VAL}"
                    }
                ]
            }
        ]
    }
}
EOM

# read back to check configuration was set
curl -i --user my-admin@example.com:my-secret -H "Accept:application/yang-data+json" ${BOOTSTRAP_URL} > /tmp/running_before.json

# change boot image from https://www.watsen.net/docs/sztpd/current/admin-guide/#example-put-ing-an-entry-before-another-entry
curl -i -X PUT --user my-admin@example.com:my-secret --data @/tmp/boot-images.json -H 'Content-Type:application/yang-data+json' ${BOOTSTRAP_URL}/wn-sztpd-1:boot-images | tee /tmp/result.json

# read back to check configuration was set
curl -i --user my-admin@example.com:my-secret -H "Accept:application/yang-data+json" ${BOOTSTRAP_URL} > /tmp/running_after.json

diff /tmp/running_before.json /tmp/running_after.json && echo ERROR && exit 1

rm -rf /tmp/boot-images.json /tmp/result.json /tmp/running_before.json /tmp/running_after.json

echo "DONE"
