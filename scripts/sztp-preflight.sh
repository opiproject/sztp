#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco Systems, Inc.
# sztp-preflight.sh
#
# End-to-end readiness check for the SZTP stack, to be run BEFORE reloading
# the target device. Each failure prints a single concrete next action.
#
# Usage:
#   scripts/sztp-preflight.sh [--env-file config/catalyst/c9300.env]
#
# Env (all optional, with safe defaults):
#   SZTP_URL                https:// URL advertised in DHCP option 143
#   BOOTSTRAP_CONTAINER     default: sztp-bootstrap-1
#   REDIRECTER_CONTAINER    default: sztp-redirecter-1
#   DHCP_CONTAINER          default: sztp-dhcp-iosxe-1
#   NBI_BOOTSTRAP_PORT      default: 7080
#   NBI_REDIRECTER_PORT     default: 7070
#   NBI_CREDS               default: my-admin@example.com:my-secret
#   DHCP_CONF_PATH          default: /data/dhcpd.conf (inside DHCP_CONTAINER)
#
# Exit 0 = green; non-zero = at least one blocking issue.

set -u

# shellcheck disable=SC2034  # ENV_FILE read by sourcing below
ENV_FILE=""
while (( $# > 0 )); do
    case "$1" in
        --env-file) ENV_FILE="$2"; shift 2 ;;
        -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
        *) printf 'unknown arg: %s\n' "$1" >&2; exit 2 ;;
    esac
done

if [[ -n "$ENV_FILE" ]]; then
    set -a
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    set +a
fi

SZTP_URL="${SZTP_URL:-https://10.127.127.3:8080}"
BOOTSTRAP_CONTAINER="${BOOTSTRAP_CONTAINER:-sztp-bootstrap-1}"
REDIRECTER_CONTAINER="${REDIRECTER_CONTAINER:-sztp-redirecter-1}"
DHCP_CONTAINER="${DHCP_CONTAINER:-sztp-dhcp-iosxe-1}"
NBI_BOOTSTRAP_PORT="${NBI_BOOTSTRAP_PORT:-7080}"
NBI_REDIRECTER_PORT="${NBI_REDIRECTER_PORT:-7070}"
NBI_CREDS="${NBI_CREDS:-my-admin@example.com:my-secret}"
DHCP_CONF_PATH="${DHCP_CONF_PATH:-/data/dhcpd.conf}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VALIDATOR="${REPO_ROOT}/scripts/validate-sztp-artifacts.sh"

fail_count=0
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n    → %s\n' "$1" "$2" >&2; fail_count=$((fail_count + 1)); }

# 1. Artifact validator (structural checks)
printf '\n[1/6] artifact bundle\n'
# Forward the voucher path from the env file. The env var SZTP_VOUCHER_FILE is a
# /local_files/... container path; the validator wants a host path in
# SZTP_VOUCHER_FILE_LOCAL. Empty falls back to the validator's own default.
voucher_local="${SZTP_VOUCHER_FILE_LOCAL:-}"
if [ -z "$voucher_local" ] && [ -n "${SZTP_VOUCHER_FILE:-}" ]; then
    voucher_local="${REPO_ROOT}/local_files/$(basename "$SZTP_VOUCHER_FILE")"
fi
if SZTP_VOUCHER_FILE_LOCAL="$voucher_local" "$VALIDATOR" "${REPO_ROOT}/local_files" >/dev/null 2>&1; then
    pass "scripts/validate-sztp-artifacts.sh passed"
else
    fail "artifact validator failed" "run: $VALIDATOR"
fi

# 2. Container health
printf '\n[2/6] container health\n'
check_container() {
    local name="$1"
    local status
    status="$(docker inspect -f '{{.State.Health.Status}}' "$name" 2>/dev/null || echo missing)"
    case "$status" in
        healthy) pass "$name is healthy" ;;
        starting) fail "$name health=starting" "wait for health-check then rerun preflight" ;;
        missing)  fail "$name not running" "docker compose --profile iosxe up -d" ;;
        *)        fail "$name health=$status" "docker logs $name" ;;
    esac
}
check_container "$BOOTSTRAP_CONTAINER"
check_container "$REDIRECTER_CONTAINER"
if ! docker inspect "$DHCP_CONTAINER" >/dev/null 2>&1; then
    fail "$DHCP_CONTAINER not running" "docker compose --profile iosxe up -d dhcp-iosxe"
else
    pass "$DHCP_CONTAINER is running"
fi

# 3. RESTCONF reachability (NBI)
printf '\n[3/6] NBI reachability\n'
check_nbi() {
    local name="$1" port="$2"
    if docker exec "$name" curl -fsS -u "$NBI_CREDS" \
        "http://127.0.0.1:${port}/.well-known/host-meta" \
        -H 'Accept: application/yang-data+json' >/dev/null 2>&1; then
        pass "$name NBI (:$port) responds"
    else
        fail "$name NBI (:$port) unreachable" "docker logs $name | tail -50"
    fi
}
check_nbi "$BOOTSTRAP_CONTAINER" "$NBI_BOOTSTRAP_PORT"
check_nbi "$REDIRECTER_CONTAINER" "$NBI_REDIRECTER_PORT"

# 4. DHCP serving option 143 matching SZTP_URL
printf '\n[4/6] DHCP option 143 payload\n'
# Expected payload via the shared encoder (validates https/no-path/ASCII/length).
if ! expected_hex="$(SZTP_URL="$SZTP_URL" "${REPO_ROOT}/scripts/option143-encode.sh" --format hex 2>/dev/null)" || [[ -z "$expected_hex" ]]; then
    fail "SZTP_URL=$SZTP_URL is not a valid https URI" "must be https://host:port (no path)"
else
    rendered="$(docker exec "$DHCP_CONTAINER" cat "$DHCP_CONF_PATH" 2>/dev/null \
        | awk '/sztp-redirect-urls/ {print $NF}' \
        | tr -d ';' | tr -d ':' | tr '[:upper:]' '[:lower:]' \
        | grep -E '^[0-9a-f]+$' | tail -1)"
    if [[ "$rendered" == "$expected_hex" ]]; then
        pass "dhcpd.conf option 143 matches SZTP_URL=$SZTP_URL"
    else
        fail "dhcpd.conf option 143 != expected encoding of $SZTP_URL" \
            "rerun dhcp-render: docker compose --profile iosxe up --force-recreate -d dhcp-render dhcp (got='$rendered' expected='$expected_hex')"
    fi
fi

# 5. Bootstrap + redirecter SBI TLS certs present
printf '\n[5/6] SBI TLS cert\n'
for c in "$BOOTSTRAP_CONTAINER" "$REDIRECTER_CONTAINER"; do
    if docker exec "$c" test -s /certs/my_cert.pem 2>/dev/null; then
        pass "$c has /certs/my_cert.pem"
    else
        fail "$c missing /certs/my_cert.pem" "setup-cert sidecar failed; docker logs sztp-setup-cert-1"
    fi
done

# 6. Device registered in both datastores
printf '\n[6/6] device registration (SZTP_DEVICE_SN=%s)\n' "${SZTP_DEVICE_SN:-<unset>}"
sn="${SZTP_DEVICE_SN:-C9300-24T}"
for pair in "$REDIRECTER_CONTAINER:$NBI_REDIRECTER_PORT" "$BOOTSTRAP_CONTAINER:$NBI_BOOTSTRAP_PORT"; do
    name="${pair%:*}"; port="${pair##*:}"
    if docker exec "$name" curl -fsS -u "$NBI_CREDS" \
        "http://127.0.0.1:${port}/restconf/ds/ietf-datastores:running/wn-sztpd-1:devices/device=${sn}" \
        -H 'Accept: application/yang-data+json' >/dev/null 2>&1; then
        pass "$name has device '$sn' registered"
    else
        fail "$name has no device '$sn'" \
            "register it via RESTCONF or set SZTP_DEVICE_SN and recreate containers"
    fi
done

printf '\n'
if (( fail_count == 0 )); then
    printf 'Preflight PASSED — safe to reload the device.\n'
    exit 0
else
    printf 'Preflight FAILED with %d issue(s).\n' "$fail_count" >&2
    exit 1
fi
