# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2022 Dell Inc, or its subsidiaries.

FROM ghcr.io/opiproject/sztpd:main@sha256:43573286ae3ea929293d0a1e275915db6b8558abdaeefe3171b554391e153add

RUN apt-get update && apt-get install -y --no-install-recommends make && rm -rf /var/lib/apt/lists/*

# certificates
SHELL ["/bin/bash", "-eo", "pipefail", "-c"]
RUN curl -kL https://watsen.net/support/sztpd-simulator-0.0.11.tgz | tar -zxvf - -C /tmp/
WORKDIR /tmp/sztpd-simulator/pki
RUN echo "DNS.2 = bootstrap" >> sztpd1/sbi/end-entity/openssl.cnf && \
    echo "DNS.3 = web" >> sztpd1/sbi/end-entity/openssl.cnf && \
    echo "DNS.4 = redirecter" >> sztpd1/sbi/end-entity/openssl.cnf && \
    make pki && \
    echo SBI Port certificates && \
    cat sztpd1/sbi/end-entity/my_cert.pem sztpd1/sbi/intermediate2/my_cert.pem > /tmp/cert_chain.pem && \
    openssl crl2pkcs7 -nocrl -certfile /tmp/cert_chain.pem -outform DER -out /tmp/cert_chain.cms && \
    echo client cert DevID trust anchor && \
    cat client/root-ca/my_cert.pem client/intermediate1/my_cert.pem client/intermediate2/my_cert.pem > /tmp/ta_cert_chain.pem && \
    openssl crl2pkcs7 -nocrl -certfile /tmp/ta_cert_chain.pem -outform DER -out /tmp/ta_cert_chain.cms && \
    echo TODO: remove this line and run test from agent container instead && \
    cat sztpd1/sbi/root-ca/my_cert.pem sztpd1/sbi/intermediate1/my_cert.pem > /opi.pem

# configurations, images, templates
COPY config/ /tmp/

# generate static template

# hadolint ignore=SC2016
RUN \
    SBI_PRI_KEY_B64=`openssl enc -base64 -A -in sztpd1/sbi/end-entity/private_key.der` \
    SBI_PUB_KEY_B64=`openssl enc -base64 -A -in sztpd1/sbi/end-entity/public_key.der` \
    SBI_EE_CERT_B64=`openssl enc -base64 -A -in /tmp/cert_chain.cms` \
    BOOTSVR_TA_CERT_B64=`openssl enc -base64 -A -in /tmp/ta_cert_chain.cms` \
    CLIENT_CERT_TA_B64=`openssl enc -base64 -A -in /tmp/ta_cert_chain.cms` \
    envsubst '$CLIENT_CERT_TA_B64,$SBI_PRI_KEY_B64,$SBI_PUB_KEY_B64,$SBI_EE_CERT_B64,$BOOTSVR_TA_CERT_B64' < /tmp/sztpd.redirect.json.template > /tmp/redirect.json.static && \
    BOOT_IMG_HASH_VAL=`openssl dgst -sha256 -c /tmp/my-boot-image.img | awk '{print $2}'` \
    PRE_SCRIPT_B64=`openssl enc -base64 -A -in /tmp/my-pre-configuration-script.sh` \
    POST_SCRIPT_B64=`openssl enc -base64 -A -in /tmp/my-post-configuration-script.sh` \
    CONFIG_B64=`openssl enc -base64 -A -in /tmp/my-configuration.xml` \
    SBI_PRI_KEY_B64=`openssl enc -base64 -A -in sztpd1/sbi/end-entity/private_key.der` \
    SBI_PUB_KEY_B64=`openssl enc -base64 -A -in sztpd1/sbi/end-entity/public_key.der` \
    SBI_EE_CERT_B64=`openssl enc -base64 -A -in /tmp/cert_chain.cms` \
    CLIENT_CERT_TA_B64=`openssl enc -base64 -A -in /tmp/ta_cert_chain.cms` \
    envsubst '$BOOT_IMG_HASH_VAL,$PRE_SCRIPT_B64,$POST_SCRIPT_B64,$CONFIG_B64,$CLIENT_CERT_TA_B64,$SBI_PRI_KEY_B64,$SBI_PUB_KEY_B64,$SBI_EE_CERT_B64' < /tmp/sztpd.running.json.template > /tmp/running.json.static

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
HEALTHCHECK CMD curl --fail -H Accept:application/yang-data+json http://127.0.0.1:$SZTPD_NBI_PORT/.well-known/host-meta || exit 1
