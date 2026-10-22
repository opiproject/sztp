#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco Systems, Inc.
# validate-sztp-artifacts.sh
#
# STRUCTURAL pre-flight checks for the SZTP voucher + owner-cert bundle that the
# bootstrap / redirecter containers will serve. They confirm file presence,
# encodings, and that the owner cert chains to the voucher's pinned-domain-cert.
# They do NOT verify the MASA voucher signature, nor the voucher's validity
# window / device constraints — use your MASA verification tooling for that.
#
# Checks (in order):
#   1. All required files exist.
#   2. Voucher (.vcj) is a DER PKCS#7 SignedData.
#   3. Pinned-domain-cert inside the voucher byte-matches the local file.
#   4. Owner cert chains to the pinned-domain-cert (openssl verify).
#   5. Owner private key matches owner cert (modulus / pubkey match).
#   6. owner_cert_chain.cms is a DER PKCS#7 containing both certs.
#
# Usage:
#   scripts/validate-sztp-artifacts.sh [LOCAL_FILES_DIR]
#
# Exit codes:
#   0  all checks pass
#   1  at least one check failed (see stderr for per-check remediation)
#
# Each failed check prints a concrete remediation hint on stderr.

set -u

LOCAL_DIR="${1:-local_files}"
VOUCHER="${SZTP_VOUCHER_FILE_LOCAL:-${LOCAL_DIR}/device.vcj}"
PINNED_CRT="${LOCAL_DIR}/pinned-domain-cert.crt"
OWNER_CRT="${LOCAL_DIR}/owner-certificate.crt"
OWNER_KEY="${LOCAL_DIR}/owner-certificate.key"
OWNER_CHAIN_CMS="${LOCAL_DIR}/owner_cert_chain.cms"
OWNER_CHAIN_PEM="${LOCAL_DIR}/owner_cert_chain.pem"

fail_count=0
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n    → %s\n' "$1" "$2" >&2; fail_count=$((fail_count + 1)); }

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'missing required command: %s\n' "$1" >&2
        exit 1
    fi
}
need_cmd openssl

printf 'Validating SZTP artifacts in %s\n' "$LOCAL_DIR"

# 1. File existence
printf '\n[1/6] file presence\n'
for f in "$VOUCHER" "$PINNED_CRT" "$OWNER_CRT" "$OWNER_KEY" "$OWNER_CHAIN_CMS"; do
    if [[ -f "$f" ]]; then
        pass "found $f"
    else
        fail "missing $f" "create or copy it into $LOCAL_DIR"
    fi
done

# Short-circuit if core files are missing.
if (( fail_count > 0 )); then
    printf '\n%d file(s) missing — cannot run cert checks.\n' "$fail_count" >&2
    exit 1
fi

# 2. Voucher is DER PKCS#7
printf '\n[2/6] voucher CMS envelope\n'
if openssl pkcs7 -inform DER -in "$VOUCHER" -noout 2>/dev/null; then
    pass "voucher parses as DER PKCS#7 ($VOUCHER)"
else
    fail "voucher is not DER PKCS#7 ($VOUCHER)" "must be a MASA-signed .vcj file; re-download from your MASA"
fi

# 3. Voucher's pinned-domain-cert matches local pinned-domain-cert.crt
printf '\n[3/6] pinned-domain-cert match\n'
if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import pyasn1_modules' 2>/dev/null; then
    printf '  skip (needs python3 + pyasn1 to parse the voucher ASN.1)\n'
else
voucher_pd_sha1="$(python3 - "$VOUCHER" <<'PY' 2>/dev/null
import base64, hashlib, json, sys
from pyasn1.codec.der.decoder import decode as der_decode
try:
    from pyasn1_modules import rfc5652
except ImportError:
    sys.exit("pyasn1_modules not available")

data = open(sys.argv[1], "rb").read()
ci, _ = der_decode(data, asn1Spec=rfc5652.ContentInfo())
sd, _ = der_decode(bytes(ci["content"]), asn1Spec=rfc5652.SignedData())
# The voucher's eContent is a JSON voucher artifact (RFC 8366).
econtent = bytes(sd["encapContentInfo"]["eContent"])
voucher_json = json.loads(econtent)
pd = voucher_json["ietf-voucher:voucher"].get("pinned-domain-cert")
if not pd:
    sys.exit("no pinned-domain-cert in voucher")
print(hashlib.sha1(base64.b64decode(pd)).hexdigest())
PY
)"
local_pd_sha1="$(openssl x509 -in "$PINNED_CRT" -outform DER 2>/dev/null | sha1sum | awk '{print $1}')"

if [[ -n "$voucher_pd_sha1" && -n "$local_pd_sha1" && "$voucher_pd_sha1" == "$local_pd_sha1" ]]; then
    pass "pinned-domain-cert byte-matches (sha1=$voucher_pd_sha1)"
else
    fail "voucher pinned-domain-cert != $PINNED_CRT (voucher=$voucher_pd_sha1 local=$local_pd_sha1)" \
        "regenerate the voucher OR replace $PINNED_CRT with the one in the voucher"
fi
fi

# 4. Owner cert chains to pinned-domain-cert
printf '\n[4/6] owner-cert chain verify\n'
verify_out="$(openssl verify -CAfile "$PINNED_CRT" "$OWNER_CRT" 2>&1)"
if [[ "$verify_out" == *": OK"* ]]; then
    pass "openssl verify: $verify_out"
else
    fail "owner cert does not verify against $PINNED_CRT" \
        "owner-certificate.crt must be signed by pinned-domain-cert.crt (issuer DN + key). Regenerate. openssl output: $verify_out"
fi

# 5. Owner private key matches owner cert
printf '\n[5/6] owner key/cert match\n'
cert_pub_sha="$(openssl x509 -in "$OWNER_CRT" -noout -pubkey 2>/dev/null | openssl sha256 | awk '{print $NF}')"
key_pub_sha="$(openssl pkey -in "$OWNER_KEY" -pubout 2>/dev/null | openssl sha256 | awk '{print $NF}')"
if [[ -n "$cert_pub_sha" && "$cert_pub_sha" == "$key_pub_sha" ]]; then
    pass "owner key matches owner cert (pubkey sha256=$cert_pub_sha)"
else
    fail "owner key does not match owner cert" \
        "$OWNER_KEY is not the private key for $OWNER_CRT. Regenerate pair together."
fi

# 6. owner_cert_chain.cms parses & contains both certs
printf '\n[6/6] owner_cert_chain.cms structure\n'
cms_cert_count="$(openssl pkcs7 -inform DER -in "$OWNER_CHAIN_CMS" -print_certs 2>/dev/null | grep -c '^subject=')"
if (( cms_cert_count >= 2 )); then
    pass "$OWNER_CHAIN_CMS contains $cms_cert_count certificates"
else
    fail "$OWNER_CHAIN_CMS contains $cms_cert_count cert(s), expected ≥2 (owner + pinned-domain)" \
        "rebuild with: openssl crl2pkcs7 -nocrl -certfile $OWNER_CHAIN_PEM -out $OWNER_CHAIN_CMS -outform DER"
fi

printf '\n'
if (( fail_count == 0 )); then
    printf 'All structural checks passed (MASA voucher signature not verified).\n'
    exit 0
else
    printf '%d check(s) failed.\n' "$fail_count" >&2
    exit 1
fi
