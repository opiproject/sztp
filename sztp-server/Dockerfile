# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2022 Dell Inc, or its subsidiaries.

FROM ghcr.io/opiproject/sztpd:main@sha256:3486f2ae45bb2535d86bc03aa63cc520ad8b556960cc69b309f8320e01e59653

# configurations, images, templates
COPY config/ /tmp/

# hadolint ignore=SC2016
RUN \
    cp /tmp/sztpd.redirect.json.template /tmp/redirect.json.configs && \
    PRE_SCRIPT_B64=`openssl enc -base64 -A -in /tmp/my-pre-configuration-script.sh` \
    POST_SCRIPT_B64=`openssl enc -base64 -A -in /tmp/my-post-configuration-script.sh` \
    CONFIG_B64=`openssl enc -base64 -A -in /tmp/my-configuration.xml` \
    envsubst '$PRE_SCRIPT_B64,$POST_SCRIPT_B64,$CONFIG_B64' < /tmp/sztpd.running.json.template > /tmp/running.json.configs

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
HEALTHCHECK CMD curl --fail -H Accept:application/yang-data+json http://127.0.0.1:$SZTPD_NBI_PORT/.well-known/host-meta || exit 1
