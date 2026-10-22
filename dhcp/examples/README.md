# DHCP snippets — RFC 8572 §8.2 option 143

The bundled `dhcp` service in `docker-compose.yml` is the turn-key lab path.
If you already run a DHCP server elsewhere (ISC dhcpd, IOS / IOS-XE switch
acting as DHCP server, etc.), use these snippets instead.

Payload encoding is **not** optional: IOS-XE SZTP rejects option 143 unless
it is a length-prefixed URI list per RFC 8572 §8.2. Regenerate the payload
for your own URL(s) via the encoder:

```bash
# ISC dhcpd binary literal ("00:15:68:74:..."), run from sztp-agent/:
go run . option143 https://bootstrap.example.com:8080

# Cisco IOS dotted-hex ("0015.6874.7470..."):
go run . option143 --format ios https://bootstrap.example.com:8080
```

Multiple URIs (fail-over list) — space-separate them:

```bash
go run . option143 \
    https://primary.example.com:8080 \
    https://secondary.example.com:8080
```

## Files

- `isc-dhcpd.snippet.conf` — paste into ISC dhcpd.
- `ios-xe-dhcp-pool.txt` — paste into Cisco IOS / IOS-XE running config.

## Relay

If the switch being provisioned is not on the same L2 as the DHCP server,
configure a DHCP relay agent (`ip helper-address <dhcp-server-ip>`) on the
client's default-gateway interface. Option 143 passes through relays
unchanged.
