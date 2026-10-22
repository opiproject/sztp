# Catalyst platform env bundles

Each `.env` file selects the trust-anchor bag and default PID for one
Catalyst generation. They drive the Phase C env-driven placeholders in
`config/sztpd.redirect.json.template` and `config/sztpd.running.json.template`.

| file            | trust anchor  | typical PID  | SUDI generation         |
|-----------------|---------------|--------------|-------------------------|
| `c9200.env`     | `act2-sudi`   | `C9200-24T`  | ACT2 (SHA-1)            |
| `c9300.env`     | `act2-sudi`   | `C9300-24T`  | ACT2 (SHA-1)            |
| `c9300x.env`    | `circa-2020`  | `C9300X-24Y` | HA-SUDI (SHA-256)       |

Usage:

```bash
docker compose --env-file config/catalyst/c9300.env --profile iosxe up -d
```

Override individual values from your shell:

```bash
SZTP_DEVICE_SN=C9300-48T \
  docker compose --env-file config/catalyst/c9300.env --profile iosxe up -d
```

Selecting the correct trust anchor is mandatory — the wrong anchor produces a
TLS handshake failure during bootstrap. Extract the device's SUDI
subject `serialNumber` (OID 2.5.4.5) with:

```bash
openssl x509 -in sudi-leaf.pem -noout -subject -nameopt multiline \
  | grep serialNumber
```

Use whatever string `get_attributes_for_oid(2.5.4.5)[0].value.split(' ')[0]`
produces (typically the Cisco PID, e.g. `C9300-24T`) as `SZTP_DEVICE_SN`.
