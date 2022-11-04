#!/bin/sh
set -e -u -x

wait_curl () {
    for i in $(seq 1 10)
    do
        echo "Attempt $i"
        if curl --fail -H Accept:application/yang-data+json http://127.0.0.1:"${SZTPD_INIT_PORT}"/.well-known/host-meta
        then
            return 0
        else
            sleep 1
        fi
    done
    return 1
}

env

# shellcheck disable=SC2016
envsubst '$SZTPD_INIT_PORT,$SZTPD_SBI_PORT,$SZTPD_INIT_ADDR,$BOOTSVR_PORT,$BOOTSVR_ADDR' < /tmp/"${SZTPD_OPI_MODE}".json.static > /tmp/running.json
diff /tmp/"${SZTPD_OPI_MODE}".json.static /tmp/running.json || true

echo "starting server in the background"
sztpd sqlite:///:memory: 2>&1 &

echo "waiting for server to start"
wait_curl

echo "sending configuration file to server"
curl -i -X PUT --user my-admin@example.com:my-secret --data @/tmp/running.json -H 'Content-Type:application/yang-data+json' http://127.0.0.1:"${SZTPD_INIT_PORT}"/restconf/ds/ietf-datastores:running

echo "waiting for server to re-start"
wait_curl

wait
