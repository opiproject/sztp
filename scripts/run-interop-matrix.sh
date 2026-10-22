#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco Systems, Inc.
# run-interop-matrix.sh
#
# Server-side STACK-PREFLIGHT matrix. For each row in config/interop-matrix.yaml,
# it renders the option-143 payload and runs the stack preflight, recording
# pass / fail / skip plus captured artifacts. It is NOT device interop evidence.
#
# NOTE: this script does NOT power-cycle or reload the target device.
# It only verifies the server-side stack is correctly configured for
# each row. Actual device runs are tracked manually in the row's
# `status` field.
#
# Usage:
#   scripts/run-interop-matrix.sh [--row <id>] [--out <dir>]
#
# Output directory layout:
#   <out>/
#     <row-id>/
#       preflight.log
#       dhcpd.conf.snippet
#       status.txt
#     summary.md

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MATRIX="${REPO_ROOT}/config/interop-matrix.yaml"
OUT_DIR=""
ONLY_ROW=""

while (( $# > 0 )); do
    case "$1" in
        --row) ONLY_ROW="$2"; shift 2 ;;
        --out) OUT_DIR="$2"; shift 2 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) printf 'unknown arg: %s\n' "$1" >&2; exit 2 ;;
    esac
done

if [[ -z "$OUT_DIR" ]]; then
    OUT_DIR="${REPO_ROOT}/interop-results/$(date -u +%Y%m%dT%H%M%SZ)"
fi
mkdir -p "$OUT_DIR"

# YAML reader (no external deps): emits tab-separated rows on stdout.
ROWS="$(awk '
function val(line) { sub(/^[^:]*:[[:space:]]*/, "", line); return line }
function emit() { if (id != "") printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", id, f["trust_anchor"], f["sztp_url"], f["sztp_device_sn"], f["voucher_file"], f["owner_cert"], f["status"] }
/^[[:space:]]*-[[:space:]]+id:/ { emit(); id = val($0); delete f; next }
/^[[:space:]]+[a-z_]+:/ { key = $1; sub(/:.*/, "", key); f[key] = val($0) }
END { emit() }
' "$MATRIX")"

SUMMARY="$OUT_DIR/summary.md"
{
    printf '# Stack-preflight matrix run — %s\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'Server-side stack checks only — not device interop evidence. '
    # shellcheck disable=SC2016  # literal markdown backticks, not command substitution
    printf 'Preflight: `pass`/`fail` = evaluated against a running stack; '
    # shellcheck disable=SC2016
    printf '`skip` = stack not running (not evaluated).\n\n'
    printf '| Row | Trust anchor | URL | SN | Encoder | Preflight |\n'
    printf '|---|---|---|---|---|---|\n'
} > "$SUMMARY"

overall_rc=0
while IFS=$'\t' read -r id trust url sn _voucher _owner status; do
    if [[ -n "$ONLY_ROW" && "$ONLY_ROW" != "$id" ]]; then continue; fi

    row_dir="$OUT_DIR/$id"
    mkdir -p "$row_dir"

    # Encoder check via the shared encoder (single-URI rows)
    enc_result="pass"
    enc_hex="$("$REPO_ROOT/scripts/option143-encode.sh" --format hex "$url" 2>/dev/null || true)"
    if [[ -z "$enc_hex" ]]; then enc_result="fail"; overall_rc=1; fi
    printf '%s\n' "$enc_hex" > "$row_dir/opt143.hex"

    # Colon-hex snippet for this row (doesn't replace running dhcp).
    "$REPO_ROOT/scripts/option143-encode.sh" "$url" > "$row_dir/opt143.colon" 2>/dev/null || true

    # Preflight against the currently-running stack, with this row's env.
    preflight_result="skip"
    if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -q '^sztp-bootstrap-1$'; then
        if SZTP_URL="$url" SZTP_DEVICE_SN="$sn" SZTP_TRUST_ANCHOR="$trust" \
            "$REPO_ROOT/scripts/sztp-preflight.sh" > "$row_dir/preflight.log" 2>&1; then
            preflight_result="pass"
        else
            preflight_result="fail"
            # Preflight fail does not fail the matrix run itself — it is
            # expected for rows whose device isn't currently in the lab.
        fi
    fi

    printf '%s\t%s\n' "$id" "$status" > "$row_dir/status.txt"

    printf '| %s | %s | %s | %s | %s | %s |\n' \
        "$id" "$trust" "$url" "$sn" "$enc_result" "$preflight_result" >> "$SUMMARY"
done <<< "$ROWS"

printf 'Wrote %s\n' "$SUMMARY"
exit "$overall_rc"
