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
docker-compose exec -T dhcp cat /var/lib/dhcpd/dhcpd.leases

# let server respond
sleep 5

# tests mDNS client
docker-compose run --rm -T nmapmdnsclient
docker-compose run --rm -T nmapmdnsclient | grep sztp_avahi_1.sztp_opi

# tests dhcp client
docker-compose exec -T client cat /var/lib/dhclient/dhclient.leases
docker-compose exec -T client cat /var/lib/dhclient/dhclient.leases | grep sztp-redirect-urls
BOOTSTRAP=$(docker-compose exec -T client cat /var/lib/dhclient/dhclient.leases | grep sztp-redirect-urls | head -n 1 | awk '{print $3}' | tr -d '";')

# read back to check configuration was set
docker-compose exec -T bootstrap curl -i --user my-admin@example.com:my-secret -H "Accept:application/yang-data+json" http://redirecter:1080/restconf/ds/ietf-datastores:running

# request onboarding info (like a DPU or IPU device would) and see it is redirect
docker-compose exec -T agent curl -X POST --data @/tmp/input.json -H "Content-Type:application/yang-data+json" --user my-serial-number:my-secret --key /private_key.pem --cert /my_cert.pem --cacert /opi.pem "https://redirecter:8080/restconf/operations/ietf-sztp-bootstrap-server:get-bootstrapping-data" | tee /tmp/post_rpc_input.json

# parse the redirect reply
jq -r .\"ietf-sztp-bootstrap-server:output\".\"conveyed-information\" /tmp/post_rpc_input.json | base64 --decode | tail -n +2 | sed  '1i {' | jq . | tee /tmp/post_rpc_fixed.json

# parse the redirect reply some more
jq -r .\"ietf-sztp-conveyed-info:redirect-information\".\"bootstrap-server\"[0].\"address\" /tmp/post_rpc_fixed.json

# read back to check configuration was set
docker-compose exec -T bootstrap curl -i --user my-admin@example.com:my-secret -H "Accept:application/yang-data+json" http://bootstrap:1080/restconf/ds/ietf-datastores:running

# request onboarding info (like a DPU or IPU device would)
docker-compose exec -T agent curl -X POST --data @/tmp/input.json -H "Content-Type:application/yang-data+json" --user my-serial-number:my-secret --key /private_key.pem --cert /my_cert.pem --cacert /opi.pem "${BOOTSTRAP}" | tee /tmp/post_rpc_input.json

# parse the reply
jq -r .\"ietf-sztp-bootstrap-server:output\".\"conveyed-information\" /tmp/post_rpc_input.json | base64 --decode | tail -n +2 | sed  '1i {' | jq . | tee /tmp/post_rpc_fixed.json

# send progress
docker-compose exec -T agent curl -X POST --data @/tmp/progress.json -H "Content-Type:application/yang-data+json" --user my-serial-number:my-secret --key /private_key.pem --cert /my_cert.pem --cacert /opi.pem "${BOOTSTRAP//get-bootstrapping-data/report-progress}"

# check audit log
docker-compose exec -T bootstrap curl -i -X GET --user my-admin@example.com:my-secret  -H "Accept:application/yang-data+json" http://bootstrap:1080/restconf/ds/ietf-datastores:operational/wn-sztpd-1:audit-log

# check bootstrapping log
docker-compose exec -T bootstrap curl -i -X GET --user my-admin@example.com:my-secret  -H "Accept:application/yang-data+json" http://bootstrap:1080/restconf/ds/ietf-datastores:operational/wn-sztpd-1:devices/device=my-serial-number/bootstrapping-log

# parse the reply some more
jq -r .\"ietf-sztp-conveyed-info:onboarding-information\".\"configuration\" /tmp/post_rpc_fixed.json | base64 --decode

# parse and execute pre-configuration-script
jq -r .\"ietf-sztp-conveyed-info:onboarding-information\".\"pre-configuration-script\" /tmp/post_rpc_fixed.json | base64 --decode
jq -r .\"ietf-sztp-conveyed-info:onboarding-information\".\"pre-configuration-script\" /tmp/post_rpc_fixed.json | base64 --decode | sh | grep "inside the pre-configuration-script..."

# parse and execute post-configuration-script
jq -r .\"ietf-sztp-conveyed-info:onboarding-information\".\"post-configuration-script\" /tmp/post_rpc_fixed.json | base64 --decode
jq -r .\"ietf-sztp-conveyed-info:onboarding-information\".\"post-configuration-script\" /tmp/post_rpc_fixed.json | base64 --decode | sh | grep "inside the post-configuration-script..."

# parse image URL and SHA
jq -r .\"ietf-sztp-conveyed-info:onboarding-information\".\"boot-image\".\"download-uri\"[] /tmp/post_rpc_fixed.json
jq -r .\"ietf-sztp-conveyed-info:onboarding-information\".\"boot-image\".\"image-verification\"[] /tmp/post_rpc_fixed.json

docker-compose exec -T agent curl --fail http://web:8082/var/lib/misc/

# actually go and download the image from the web server
URL=$(jq -r .\"ietf-sztp-conveyed-info:onboarding-information\".\"boot-image\".\"download-uri\"[0] /tmp/post_rpc_fixed.json)
BASENAME=$(basename "${URL}")
docker-compose exec -T agent curl --output "/tmp/${BASENAME}" --fail "${URL}"

# Validate signature
SIGNATURE=$(docker-compose exec -T agent ash -c "openssl dgst -sha256 -c \"/tmp/${BASENAME}\" | awk '{print \$2}'")
jq -r .\"ietf-sztp-conveyed-info:onboarding-information\".\"boot-image\".\"image-verification\"[] /tmp/post_rpc_fixed.json | grep "${SIGNATURE}"

# print for debug
docker-compose ps

# test go-code
name=$(docker-compose ps | grep opi-sztp-go-agent | awk '{print $1}')
rc=$(docker wait "${name}")
if [ "${rc}" != "0" ]; then
    echo "opi-sztp-go-agent failed:"
    docker logs "${name}"
    exit 1
fi

echo "DONE"
