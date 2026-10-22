#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco Systems, Inc.
# Render /data/dhcpd.conf for the IOS-XE path.
#
# Encodes SZTP_URL via scripts/option143-encode.sh (RFC 8572 section 8.2
# option-143) and writes a minimal dhcpd.conf. No template or Python needed.
#
# Inputs (env vars):
#   SZTP_URL            Comma-separated https:// URI list (required)
#   NODE_IP_SUBNET      e.g. 10.127.127.0
#   NODE_IP_NETMASK     e.g. 255.255.255.0
#   NODE_IP_RANGE_MIN   e.g. 10.127.127.100
#   NODE_IP_RANGE_MAX   e.g. 10.127.127.253
#
# Output:
#   /data/dhcpd.conf    ISC dhcpd config with the option 143 payload.
#
# Exits non-zero on any error.

set -eu

: "${SZTP_URL:?SZTP_URL must be set (comma-separated https URIs)}"
: "${NODE_IP_SUBNET:=10.127.127.0}"
: "${NODE_IP_NETMASK:=255.255.255.0}"
: "${NODE_IP_RANGE_MIN:=10.127.127.100}"
: "${NODE_IP_RANGE_MAX:=10.127.127.253}"

OUTPUT="${OUTPUT:-/data/dhcpd.conf}"
ENCODE="${OPTION143_ENCODE:-$(dirname "$0")/option143-encode.sh}"

# RFC 8572 §8.2 option-143 payload (validates https / no-path / ASCII / length).
OPTION_143_BINARY=$(SZTP_URL="$SZTP_URL" sh "$ENCODE" --format colon)

cat > "$OUTPUT" <<EOF
# Rendered by scripts/render-dhcpd-conf.sh — do not hand-edit.
ddns-update-style interim;
ignore client-updates;
authoritative;
allow unknown-clients;

# RFC 8572 §8.2 — SZTP-Redirect URL list option.
option sztp-redirect-urls code 143 = string;

subnet ${NODE_IP_SUBNET} netmask ${NODE_IP_NETMASK} {
    range ${NODE_IP_RANGE_MIN} ${NODE_IP_RANGE_MAX};
    default-lease-time 600;
    max-lease-time 7200;
    option sztp-redirect-urls ${OPTION_143_BINARY};
}
EOF

echo "render-dhcpd-conf: wrote $OUTPUT"
echo "render-dhcpd-conf: SZTP_URL=$SZTP_URL"
echo "render-dhcpd-conf: OPTION_143_BINARY=$OPTION_143_BINARY"
