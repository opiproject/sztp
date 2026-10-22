# local_files/

Per-device crypto artifacts for Secure ZTP against real hardware. These are
**operator-supplied and secret** — the repo `.gitignore` excludes keys,
vouchers, and related material so they are never committed. This directory
ships only this README.

## Expected contents

| File | Purpose |
| --- | --- |
| `<chassis-sn>.vcj` | MASA-signed ownership voucher (RFC 8366) binding the chassis serial to the pinned-domain-cert. |
| `pinned-domain-cert.crt` | The pinned-domain-cert referenced by the voucher. |
| `owner-certificate.crt` / `owner-certificate.key` | Owner certificate and its private key. |
| `owner_cert_chain.cms` | DER PKCS#7 chain (owner + pinned-domain). |

A Catalyst env bundle points at these via `SZTP_VOUCHER_FILE` /
`SZTP_OWNER_CERT_FILE` (see [config/catalyst/](../config/catalyst/)).

## Validate before use

```sh
scripts/validate-sztp-artifacts.sh local_files
```

> Note: delivering the ownership voucher to the device requires the bootstrap
> server to emit a signed-JSON response that includes it. The stock simulator
> does not do this for every IOS-XE build — see the limitation note in
> [IOSXE.md](../IOSXE.md).
