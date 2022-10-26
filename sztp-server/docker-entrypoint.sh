#!/usr/bin/env sh
set -e -u -x

env

# shellcheck disable=SC2016
envsubst '$SZTPD_INIT_PORT,$SZTPD_SBI_PORT,$SZTPD_INIT_ADDR' < /tmp/running.json.static > /tmp/running.json
diff /tmp/running.json.static /tmp/running.json || true

echo "starting server in the background"
sztpd sqlite:///:memory: 2>&1 &

echo "waiting for server to start"
for i in $(seq 1 10)
do
    echo "Attempt $i"
    if curl --fail -H Accept:application/yang-data+json http://127.0.0.1:"${SZTPD_INIT_PORT}"/.well-known/host-meta
    then
        break
    else
        sleep 1
    fi
done

echo "sending configuration file to server"
curl -i -X PUT --user my-admin@example.com:my-secret --data @/tmp/running.json -H 'Content-Type:application/yang-data+json' http://127.0.0.1:"${SZTPD_INIT_PORT}"/restconf/ds/ietf-datastores:running

echo "waiting for server to re-start"
for i in $(seq 1 10)
do
    echo "Attempt $i"
    if curl --fail -H Accept:application/yang-data+json http://127.0.0.1:"${SZTPD_INIT_PORT}"/.well-known/host-meta
    then
        break
    else
        sleep 1
    fi
done

wait
