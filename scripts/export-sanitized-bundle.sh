#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco Systems, Inc.
# export-sanitized-bundle.sh
#
# Build a tarball of the repo suitable for sharing (e.g. with Cisco TAC,
# a peer team, or the public opiproject/sztp PR). Private keys, MASA
# vouchers, DER private keys, and other sensitive material are stripped.
# A manifest of stripped files is written into the tarball.
#
# Usage:
#   scripts/export-sanitized-bundle.sh [OUTPUT_DIR]
#
# Output:
#   <OUTPUT_DIR>/sztp-sanitized-<UTC-date>.tar.gz
#   <OUTPUT_DIR>/sztp-sanitized-<UTC-date>.manifest.txt
#
# Default OUTPUT_DIR is the parent directory of the repo.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="${1:-$(dirname "$REPO_ROOT")}"
mkdir -p "$OUTPUT_DIR"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

STAGE="$WORK/sztp"
mkdir -p "$STAGE"

# Copy the repo EXCLUDING sensitive material + volatile runtime artifacts.
# Keep .gitignore patterns authoritative — but add belt-and-suspenders here
# too in case the exporter is run with files untracked.
EXCLUDES=(
    --exclude='.git'
    --exclude='*.key'
    --exclude='*.vcj'
    --exclude='*.der'
    --exclude='*.srl'
    --exclude='*.bak.*'
    --exclude='dhcp/dhcpd.leases*'
    --exclude='iosxe-transfer-bundle-*'
    --exclude='local_files/private_key.der'
    --exclude='local_files/public_key.der'
)

tar -C "$REPO_ROOT" -cf - "${EXCLUDES[@]}" . | tar -C "$STAGE" -xf -

# Strip any file whose CONTENT is a private key (e.g. a *.pem key that the
# extension excludes above would miss). The fail-closed check below enforces it.
PEM_KEY_RE='-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----'
pem_stripped="$(grep -rlE -e "$PEM_KEY_RE" "$STAGE" 2>/dev/null || true)"
if [ -n "$pem_stripped" ]; then
    printf '%s\n' "$pem_stripped" | while IFS= read -r f; do rm -f "$f"; done
fi

# Manifest of what was stripped, relative to repo root.
MANIFEST="$OUTPUT_DIR/sztp-sanitized-${STAMP}.manifest.txt"
{
    printf '# Sanitized bundle — stripped files\n'
    printf '# Created: %s\n' "$STAMP"
    printf '# Repo: %s\n\n' "$REPO_ROOT"
    ( cd "$REPO_ROOT" && find . \
        \( -name '*.key' -o -name '*.vcj' -o -name '*.der' -o -name '*.srl' -o -name '*.bak.*' \) \
        -not -path './.git/*' | sort )
    if [ -n "$pem_stripped" ]; then
        printf '\n# Stripped by PEM private-key content scan:\n'
        printf '%s\n' "$pem_stripped" | sed "s#^$STAGE#.#"
    fi
} > "$MANIFEST"

cp "$MANIFEST" "$STAGE/SANITIZED-MANIFEST.txt"

TARBALL="$OUTPUT_DIR/sztp-sanitized-${STAMP}.tar.gz"
tar -C "$WORK" -czf "$TARBALL" sztp

printf 'Wrote %s\n' "$TARBALL"
printf 'Manifest: %s\n' "$MANIFEST"

# Safety belt (fail-closed): reject sensitive file names AND private-key PEM content.
if tar -tzf "$TARBALL" | grep -E '\.(key|vcj|der)$' >&2; then
    printf 'ERROR: sensitive files leaked into bundle (see above).\n' >&2
    exit 1
fi
if grep -rlE -e "$PEM_KEY_RE" "$STAGE" >&2 2>/dev/null; then
    printf 'ERROR: private-key PEM content leaked into bundle (see above).\n' >&2
    exit 1
fi
printf 'Leak scan: clean.\n'
