#!/bin/bash
set -e -u -x

wait_curl () {
    for i in $(seq 1 "${SZTPD_RETRY_ATTEMPTS:-10}")
    do
        echo "Attempt $i"
        if curl --fail -H Accept:application/yang-data+json http://127.0.0.1:"${1}"/.well-known/host-meta
        then
            return 0
        else
            sleep 1
        fi
    done
    return 1
}

env

declare -a names

# files and configs

# shellcheck disable=SC2043
for vendor in my
do
    names+=("${vendor^^}_BOOT_IMG_HASH_VAL" "${vendor^^}_CONFIG_B64")
    export ${vendor^^}_BOOT_IMG_HASH_VAL="$(openssl dgst -sha256 -c  ./media/${vendor,,}-boot-image.img | awk '{print $2}')"
    export ${vendor^^}_CONFIG_B64="$(openssl enc -base64 -A -in      /mnt/${vendor,,}-configuration.xml)"
    for item in pre post
    do
        names+=("${vendor^^}_${item^^}_SCRIPT_B64")
        export ${vendor^^}_${item^^}_SCRIPT_B64="$(openssl enc -base64 -A -in  /mnt/${vendor,,}-${item,,}-configuration-script.sh)"
    done
done

export "${names[@]}"
# shellcheck disable=SC2016
envsubst "$(printf '${%s} ' "${names[@]}")" < /mnt/sztpd."${SZTPD_OPI_MODE}".json.template > /tmp/"${SZTPD_OPI_MODE}".json.images

# check what changed
diff /mnt/sztpd."${SZTPD_OPI_MODE}".json.template /tmp/"${SZTPD_OPI_MODE}".json.images || true

# shellcheck disable=SC2016
SBI_PRI_KEY_B64=$(openssl enc -base64 -A -in /certs/private_key.der) \
SBI_PUB_KEY_B64=$(openssl enc -base64 -A -in /certs/public_key.der) \
SBI_EE_CERT_B64=$(openssl enc -base64 -A -in /certs/cert_chain.cms) \
BOOTSVR_TA_CERT_B64=$(openssl enc -base64 -A -in /certs/ta_cert_chain.cms) \
CLIENT_CERT_TA_B64=$(openssl enc -base64 -A -in /certs/ta_cert_chain.cms) \
envsubst '$CLIENT_CERT_TA_B64,$SBI_PRI_KEY_B64,$SBI_PUB_KEY_B64,$SBI_EE_CERT_B64,$BOOTSVR_TA_CERT_B64' < /tmp/"${SZTPD_OPI_MODE}".json.images > /tmp/"${SZTPD_OPI_MODE}".json.keys
diff /tmp/"${SZTPD_OPI_MODE}".json.images /tmp/"${SZTPD_OPI_MODE}".json.keys || true

# shellcheck disable=SC2016
envsubst '$SZTPD_INIT_PORT,$SZTPD_NBI_PORT,$SZTPD_SBI_PORT,$SZTPD_INIT_ADDR,$BOOTSVR_PORT,$BOOTSVR_ADDR' < /tmp/"${SZTPD_OPI_MODE}".json.keys > /tmp/running.json
diff /tmp/"${SZTPD_OPI_MODE}".json.keys /tmp/running.json || true

echo "starting server in the background"
sztpd sqlite:///:memory: 2>&1 &

echo "waiting for server to start"
wait_curl "${SZTPD_INIT_PORT}"

echo "sending configuration file to server"
curl -i -X PUT --user my-admin@example.com:my-secret --data @/tmp/running.json -H 'Content-Type:application/yang-data+json' http://127.0.0.1:"${SZTPD_INIT_PORT}"/restconf/ds/ietf-datastores:running

echo "waiting for server to re-start"
wait_curl "${SZTPD_NBI_PORT}"

wait
