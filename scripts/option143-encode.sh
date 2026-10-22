#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco Systems, Inc.
# option143-encode.sh — encode https:// URIs as an RFC 8572 section 8.2 DHCPv4
# option-143 payload. POSIX-shell mirror of sztp-agent/pkg/dhcp.EncodeOption143
# for environments without the Go toolchain (the dhcp-render container and the
# preflight / matrix helpers).
#
# Usage:
#   option143-encode.sh [--format colon|hex] <https-uri> [https-uri ...]
#   SZTP_URL="https://a:8080,https://b:9090" option143-encode.sh [--format ...]
#
# Enforces https:// scheme, scheme+host+port only (no path), ASCII, and the
# 65535-byte per-URI limit. Exits non-zero on invalid input.

set -eu

fmt="colon"
if [ "${1:-}" = "--format" ]; then
    fmt="${2:?--format needs a value}"
    shift 2
fi

acc=""

encode_one() {
    u=$(printf '%s' "$1" | tr -d ' ')
    [ -z "$u" ] && return 0
    case "$u" in
        https://*) ;;
        *) echo "option143-encode: URI must be https:// ($u)" >&2; exit 2 ;;
    esac
    case "${u#https://}" in
        */*) echo "option143-encode: host:port only, no path ($u)" >&2; exit 2 ;;
    esac
    if printf '%s' "$u" | LC_ALL=C grep -q '[^ -~]'; then
        echo "option143-encode: URI must be ASCII ($u)" >&2; exit 2
    fi
    len=$(printf '%s' "$u" | wc -c | tr -d ' ')
    if [ "$len" -gt 65535 ]; then
        echo "option143-encode: URI length $len exceeds 65535-byte limit" >&2; exit 2
    fi
    body=$(printf '%s' "$u" | od -A n -t x1 | tr -d ' \n')
    acc="${acc}$(printf '%04x' "$len")${body}"
}

if [ "$#" -gt 0 ]; then
    for uri in "$@"; do encode_one "$uri"; done
else
    oldIFS=$IFS
    IFS=','
    # shellcheck disable=SC2086  # intentional split on IFS=',' over SZTP_URL
    for uri in ${SZTP_URL:?provide URIs as arguments or set SZTP_URL}; do
        IFS=$oldIFS
        encode_one "$uri"
        IFS=','
    done
    IFS=$oldIFS
fi

[ -n "$acc" ] || { echo "option143-encode: at least one URI is required" >&2; exit 2; }

case "$fmt" in
    hex)   printf '%s\n' "$acc" ;;
    colon) printf '%s\n' "$acc" | sed 's/../&:/g; s/:$//' ;;
    *)     echo "option143-encode: unknown --format '$fmt' (want colon or hex)" >&2; exit 2 ;;
esac
