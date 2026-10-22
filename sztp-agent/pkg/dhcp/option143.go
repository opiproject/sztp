/*
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Cisco Systems, Inc.
*/

package dhcp

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// EncodeOption143 encodes one or more https:// URIs as an RFC 8572 section 8.2
// DHCPv4 option 143 payload: for each URI a uint16 big-endian length prefix
// followed by the UTF-8 URI bytes, all concatenated.
func EncodeOption143(uris []string) ([]byte, error) {
	cleaned := make([]string, 0, len(uris))
	for _, u := range uris {
		if u = strings.TrimSpace(u); u != "" {
			cleaned = append(cleaned, u)
		}
	}
	if len(cleaned) == 0 {
		return nil, fmt.Errorf("at least one URI is required")
	}

	out := make([]byte, 0)
	for _, u := range cleaned {
		if !strings.HasPrefix(u, "https://") {
			return nil, fmt.Errorf("URI must start with https:// (got %q)", u)
		}
		for _, r := range u {
			if r > 0x7f {
				return nil, fmt.Errorf("URI must be ASCII: %q", u)
			}
		}
		b := []byte(u)
		if len(b) > 0xFFFF {
			return nil, fmt.Errorf("URI length %d exceeds 65535-byte uint16 limit", len(b))
		}
		// len(b) is bounded to <= 0xFFFF above, so both length bytes fit.
		out = append(out, byte(len(b)>>8), byte(len(b))) //nolint:gosec // length bounded above
		out = append(out, b...)
	}
	return out, nil
}

// FormatColon renders the payload as an ISC dhcpd colon-hex literal
// ("00:15:68:..."), the default for a dhcpd option declaration.
func FormatColon(payload []byte) string {
	parts := make([]string, len(payload))
	for i, b := range payload {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

// FormatHex renders the payload as plain lower-case hex with no separators.
func FormatHex(payload []byte) string {
	return hex.EncodeToString(payload)
}

// FormatIOS renders the payload as Cisco IOS dotted-hex, grouped two bytes at
// a time ("0019.6874.7470...").
func FormatIOS(payload []byte) string {
	h := hex.EncodeToString(payload)
	groups := make([]string, 0, (len(h)+3)/4)
	for i := 0; i < len(h); i += 4 {
		end := i + 4
		if end > len(h) {
			end = len(h)
		}
		groups = append(groups, h[i:end])
	}
	return strings.Join(groups, ".")
}
