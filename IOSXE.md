# Secure ZTP against Cisco IOS-XE (Catalyst)

How to point this reference stack at a physical Cisco Catalyst switch
(9200 / 9300 / 9300X running IOS-XE 17.x) and have it fetch bootstrapping
data over RFC 8572 Secure ZTP.

This guide covers the vendor-neutral enablement shipped in this repo: the
DHCPv4 option-143 encoder, the opt-in `iosxe` Compose profile, the Catalyst
env bundles, and the preflight/validator helpers. See [ZTP.md](ZTP.md) for
generic ZTP background.

## 1. The non-obvious rules (read this first)

Four things trip up almost everyone pointing sZTP at IOS-XE. Each is cheap
to verify.

1. **DHCP option 143 must use RFC 8572 §8.2 binary framing.** IOS-XE 17.x
   silently drops a plain-`text` URL — the autoinstall log shows only
   `si-addr`, never `bootstrap-server-list:`. The on-the-wire bytes are a
   concatenation of one record per URI:

   ```text
   uint16_BE_length || URI_bytes (UTF-8)
   ```

   Generate them with the `option143` subcommand of the sztp-agent CLI;
   never hand-write a quoted URL.

2. **Redirect URL is scheme + host + port only — no path.** The switch
   appends the RESTCONF path itself. Including the path yields a doubled URL
   and a `404 Unrecognized RPC`.

   - ✅ `https://bootstrap.example.com:8080`
   - ❌ `https://bootstrap.example.com:8080/restconf/operations/...`

3. **Register the device under its PID, not its chassis serial.** sZTPD
   identifies a device from the SUDI client cert's `Subject.serialNumber`
   (OID 2.5.4.5), which on Catalyst is `PID:<model> SN:<chassis-sn>`. sZTPD
   splits on the first space, so the registration key is the **PID**
   (e.g. `C9300-24T`). The chassis SN only names the voucher file.

4. **Match the trust anchor to the device's SUDI generation** (see §4).

## 2. Prerequisites

- Docker + Docker Compose v2.
- A DHCP path from the switch to this host (same L2, or a relay with
  `ip helper-address`).
- The device's MASA-issued ownership voucher and owner-cert chain placed in
  `local_files/` (see §5).

## 3. DHCP option 143

Pick one of two ways to serve it.

### 3.1 Turn-key: the `iosxe` Compose profile

The `iosxe` profile encodes `$SZTP_URL` and serves option 143 over host
networking, so DHCPDISCOVERs from a physical switch are received on the lab
NIC. The default profile is unchanged — these services only start when the
profile is selected.

```sh
SZTP_URL=https://bootstrap.example.com:8080 \
  docker compose --profile iosxe up -d
```

The `dhcp-iosxe` service uses host networking, bound to a single NIC via
`DHCP_IFACE` (default `eth0`). Serving DHCP onto a physical L2 requires either
host networking or a macvlan network; host mode is simplest for a lab. For a
hardened setup, attach the service to a `macvlan` network on the lab NIC
instead of `network_mode: host`.

### 3.2 Bring your own DHCP server

If you already run ISC dhcpd or use the switch as the DHCP server, encode the
payload and paste it in. See [dhcp/examples/](dhcp/examples/) for ready-made
snippets.

```sh
# ISC dhcpd binary literal (run from sztp-agent/):
go run . option143 https://bootstrap.example.com:8080

# Cisco IOS dotted-hex:
go run . option143 --format ios https://bootstrap.example.com:8080
```

> Do **not** also set `option bootfile-name` (option 67). Classic ZTP wins
> over sZTP and the switch downloads a config script instead.

## 4. Trust anchor selection

Identify the device's SUDI generation on the switch:

```text
Switch# show platform sudi certificate sign nonce 1
Switch# show crypto pki trustpool policy | include CA
```

| Switch reports | SUDI generation | Catalyst env bundle |
| --- | --- | --- |
| Cisco Root CA 2048 + ACT2 SUDI CA | ACT2 (SHA-1) | `config/catalyst/c9300.env` |
| Cisco Root CA 2099 + High Assurance SUDI CA | HA-SUDI (SHA-256) | `config/catalyst/c9300x.env` |

The env bundle sets `SZTP_TRUST_ANCHOR` for you. A wrong anchor produces
`Client cert ... does not validate using trust anchors` on the switch.

## 5. Crypto artifacts and preflight

Place the per-device files in `local_files/` and validate the bundle before
reloading the switch:

```sh
scripts/validate-sztp-artifacts.sh
scripts/sztp-preflight.sh --env-file config/catalyst/c9300.env
```

`validate-sztp-artifacts.sh` runs six checks on the voucher + owner-cert
chain; `sztp-preflight.sh` checks the running stack end-to-end. A `401
access-denied` from the bootstrap endpoint is expected and healthy — it means
mTLS is enforced and the endpoint is reachable.

## 6. Reload and watch

Everything the switch does is in one log:

```text
Switch# show logging process sztp internal start last 20 minutes
```

The success signal is the hostname changing (e.g. to `sztp-provisioning`)
after the switch applies the onboarding configuration.

## 7. Error → fix lookup table

| Log line (host or switch) | Root cause | Fix |
| --- | --- | --- |
| Switch: only `si-addr`, no `bootstrap-server-list` | Option 143 missing or `text`-encoded | Re-encode with `sztp-agent option143`; verify on the wire |
| Switch: `bootfile: http://...` appears | Classic ZTP option 67 wins | Remove `option bootfile-name` from the DHCP config |
| Host: `Server response is not signed` / `404` | Doubled URL — `SZTP_URL` has a path | Set `SZTP_URL=https://HOST:PORT` only |
| Host: `access-denied` (401) during provisioning | Device registered under the wrong key | Register the **PID**, not the chassis SN (§1.3) |
| Switch: `does not validate using trust anchors` | Wrong truststore (ACT2 vs HA-SUDI) | Pick the matching env bundle (§4) |
| Switch: `unable to get local issuer certificate` | Owner cert not signed by the voucher's pinned-domain-cert | Re-validate with `scripts/validate-sztp-artifacts.sh` (§5) |

## 8. Known limitation — the bootstrap simulator

This repo's bootstrap server is the Watsen `sztpd` simulator. Depending on the
IOS-XE build and SUDI generation, some devices require the conveyed-information
to be delivered as signed JSON (CMS eContent) rather than XML. If the switch
reports `Failed to parse the conveyed info xml` or `Ownership voucher is
missing`, the simulator configuration in your environment needs adjusting to
emit a signed-JSON response for that device; this is outside the scope of the
helpers documented here.

## See also

- [dhcp/examples/](dhcp/examples/) — paste-ready DHCP snippets.
- [sztp-agent/pkg/dhcp](sztp-agent/pkg/dhcp) — RFC 8572 §8.2 option-143 encoder (`sztp-agent option143`).
- [ZTP.md](ZTP.md) — generic ZTP background.
