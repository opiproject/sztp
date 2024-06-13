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
docker-compose exec -T dhcp cat /var/lib/dhcp/dhcpd.leases

# let server respond
sleep 5

# tests mDNS client
docker-compose run --rm -T nmapmdnsclient
docker-compose run --rm -T nmapmdnsclient | grep sztp_opi

# tests dhcp client
docker-compose exec -T client cat /var/lib/dhclient/dhclient.leases
docker-compose exec -T client cat /var/lib/dhclient/dhclient.leases | grep sztp-redirect-urls
REDIRECT=$(docker-compose exec -T client cat /var/lib/dhclient/dhclient.leases | grep sztp-redirect-urls | head -n 1 | awk '{print $3}' | tr -d '";')

# reusable variables
CERTIFICATES=(--key /certs/private_key.pem --cert /certs/my_cert.pem --cacert /certs/opi.pem)
SERIAL_NUMBER=third-serial-number
CREDENTIALS=(--user "${SERIAL_NUMBER}":my-secret)
NBI_CREDENTIALS=(--user my-admin@example.com:my-secret)

# TODO: remove --insecure
docker-compose run -T agent curl --insecure --fail-with-body "${CERTIFICATES[@]}" --output /tmp/first-boot-image.tst  "https://web:443/first-boot-image.img"
docker-compose run -T agent curl --insecure --fail-with-body "${CERTIFICATES[@]}" --output /tmp/second-boot-image.tst "https://web:443/second-boot-image.img"
docker-compose run -T agent curl --insecure --fail-with-body "${CERTIFICATES[@]}" --output /tmp/third-boot-image.tst  "https://web:443/third-boot-image.img"

# read back to check configuration was set
docker-compose exec -T redirecter curl --include --fail "${NBI_CREDENTIALS[@]}" -H "Accept:application/yang-data+json" http://redirecter:7070/restconf/ds/ietf-datastores:running

# request onboarding info (like a DPU or IPU device would) and see it is redirect
docker-compose run -T agent curl --request POST --fail-with-body --data '{"ietf-sztp-bootstrap-server:input":{"hw-model":"model-x","os-name":"vendor-os","os-version":"17.3R2.1","signed-data-preferred":[null],"nonce":"BASE64VALUE="}}' -H "Content-Type:application/yang-data+json" "${CREDENTIALS[@]}" "${CERTIFICATES[@]}" "${REDIRECT}" | tee /tmp/post_rpc_input.json

# parse the redirect reply
jq -r .\"ietf-sztp-bootstrap-server:output\".\"conveyed-information\" /tmp/post_rpc_input.json | base64 --decode | tail -n +2 | sed  '1i {' | jq . | tee /tmp/post_rpc_fixed.json

# parse the redirect reply some more
addr=$(jq -r .\"ietf-sztp-conveyed-info:redirect-information\".\"bootstrap-server\"[0].\"address\" /tmp/post_rpc_fixed.json)
port=$(jq -r .\"ietf-sztp-conveyed-info:redirect-information\".\"bootstrap-server\"[0].\"port\" /tmp/post_rpc_fixed.json)
# TODO: fix the const naming to regexp here
BOOTSTRAP="${REDIRECT//redirecter:8080/$addr:$port}"

# read back to check configuration was set
docker-compose exec -T bootstrap curl --include --fail "${NBI_CREDENTIALS[@]}" -H "Accept:application/yang-data+json" http://bootstrap:7080/restconf/ds/ietf-datastores:running

# request onboarding info (like a DPU or IPU device would)
docker-compose run -T agent curl --request POST --fail-with-body --data '{"ietf-sztp-bootstrap-server:input":{"hw-model":"model-x","os-name":"vendor-os","os-version":"17.3R2.1","signed-data-preferred":[null],"nonce":"BASE64VALUE="}}' -H "Content-Type:application/yang-data+json" "${CREDENTIALS[@]}" "${CERTIFICATES[@]}" "${BOOTSTRAP}" | tee /tmp/post_rpc_input.json

# parse the reply
jq -r .\"ietf-sztp-bootstrap-server:output\".\"conveyed-information\" /tmp/post_rpc_input.json | base64 --decode | tail -n +2 | sed  '1i {' | jq . | tee /tmp/post_rpc_fixed.json

# send progress
docker-compose run -T agent curl --request POST --fail-with-body --data '{"ietf-sztp-bootstrap-server:input":{"progress-type":"bootstrap-initiated","message":"message sent via JSON"}}' -H "Content-Type:application/yang-data+json" "${CREDENTIALS[@]}" "${CERTIFICATES[@]}" "${BOOTSTRAP//get-bootstrapping-data/report-progress}"

# check audit log
docker-compose exec -T bootstrap curl --include --fail -X GET "${NBI_CREDENTIALS[@]}"  -H "Accept:application/yang-data+json" http://bootstrap:7080/restconf/ds/ietf-datastores:operational/wn-sztpd-1:audit-log

# check bootstrapping log
docker-compose exec -T bootstrap curl --include --fail -X GET "${NBI_CREDENTIALS[@]}"  -H "Accept:application/yang-data+json" http://bootstrap:7080/restconf/ds/ietf-datastores:operational/wn-sztpd-1:devices/device="${SERIAL_NUMBER}"/bootstrapping-log

# parse the reply some more
jq -r .\"ietf-sztp-conveyed-info:onboarding-information\".\"configuration\" /tmp/post_rpc_fixed.json | base64 --decode

# parse and execute pre-configuration-script
jq -r .\"ietf-sztp-conveyed-info:onboarding-information\".\"pre-configuration-script\" /tmp/post_rpc_fixed.json | base64 --decode
jq -r .\"ietf-sztp-conveyed-info:onboarding-information\".\"pre-configuration-script\" /tmp/post_rpc_fixed.json | base64 --decode | sh | grep "inside the third-pre-configuration-script..."

# parse and execute post-configuration-script
jq -r .\"ietf-sztp-conveyed-info:onboarding-information\".\"post-configuration-script\" /tmp/post_rpc_fixed.json | base64 --decode
jq -r .\"ietf-sztp-conveyed-info:onboarding-information\".\"post-configuration-script\" /tmp/post_rpc_fixed.json | base64 --decode | sh | grep "inside the third-post-configuration-script..."

# parse image URL and SHA
jq -r .\"ietf-sztp-conveyed-info:onboarding-information\".\"boot-image\".\"download-uri\"[] /tmp/post_rpc_fixed.json
jq -r .\"ietf-sztp-conveyed-info:onboarding-information\".\"boot-image\".\"image-verification\"[] /tmp/post_rpc_fixed.json

# actually go and download the image from the web server
URL=$(jq -r .\"ietf-sztp-conveyed-info:onboarding-information\".\"boot-image\".\"download-uri\"[0] /tmp/post_rpc_fixed.json)
BASENAME=$(basename "${URL}")
docker-compose run -T agent curl --insecure --fail-with-body "${CERTIFICATES[@]}" --output "/tmp/${BASENAME}" "${URL}"

# Validate signature
SIGNATURE=$(docker-compose run -T agent ash -c "openssl dgst -sha256 -c \"/tmp/${BASENAME}\" | awk '{print \$2}'")
jq -r .\"ietf-sztp-conveyed-info:onboarding-information\".\"boot-image\".\"image-verification\"[] /tmp/post_rpc_fixed.json | grep "${SIGNATURE}"

# send progress
docker-compose run -T agent curl --request POST --fail-with-body --data '{"ietf-sztp-bootstrap-server:input":{"progress-type":"bootstrap-complete","message":"message sent via JSON"}}' -H "Content-Type:application/yang-data+json" "${CREDENTIALS[@]}" "${CERTIFICATES[@]}" "${BOOTSTRAP//get-bootstrapping-data/report-progress}"

# print for debug
docker-compose ps

# test go-code
name=$(docker-compose ps | grep agent | awk '{print $1}')
rc=$(docker wait "${name}")
if [ "${rc}" != "0" ]; then
    echo "agent failed:"
    docker logs "${name}"
    exit 1
fi

# check bootstrapping log
docker-compose exec -T bootstrap curl --include --request GET --fail "${NBI_CREDENTIALS[@]}"  -H "Accept:application/yang-data+json" http://bootstrap:7080/restconf/ds/ietf-datastores:operational/wn-sztpd-1:devices/device="${SERIAL_NUMBER}"/bootstrapping-log
docker-compose exec -T bootstrap curl --include --request GET --fail "${NBI_CREDENTIALS[@]}"  -H "Accept:application/yang-data+json" http://bootstrap:7080/restconf/ds/ietf-datastores:operational/wn-sztpd-1:devices/device="${SERIAL_NUMBER}"/bootstrapping-log | grep -zqv ietf-restconf:errors
docker-compose exec -T bootstrap curl --include --request GET --fail "${NBI_CREDENTIALS[@]}"  -H "Accept:application/yang-data+json" http://bootstrap:7080/restconf/ds/ietf-datastores:operational/wn-sztpd-1:devices/device="${SERIAL_NUMBER}"/bootstrapping-log | grep bootstrap-complete

echo "DONE"
