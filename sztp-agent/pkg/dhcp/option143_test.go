/*
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Cisco Systems, Inc.
*/

package dhcp

import (
	"encoding/hex"
	"strings"
	"testing"
)

const testURL = "https://10.127.127.3:8080"

func TestEncodeOption143SingleKnownVector(t *testing.T) {
	url := testURL
	payload, err := EncodeOption143([]string{url})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if payload[0] != 0x00 || int(payload[1]) != len(url) {
		t.Fatalf("length prefix wrong: %02x%02x for len %d", payload[0], payload[1], len(url))
	}
	if string(payload[2:]) != url {
		t.Fatalf("payload body mismatch: %q", string(payload[2:]))
	}
}

func TestFormatColonKnownVector(t *testing.T) {
	const want = "00:19:68:74:74:70:73:3a:2f:2f:31:30:2e:31:32:37:2e:31:32:37:2e:33:3a:38:30:38:30"
	payload, err := EncodeOption143([]string{testURL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := FormatColon(payload); got != want {
		t.Fatalf("colon format mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestEncodeOption143MultiURIConcatenates(t *testing.T) {
	urls := []string{"https://a.example:8080", "https://b.example:9090"}
	payload, err := EncodeOption143(urls)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	off := 0
	for _, u := range urls {
		length := int(payload[off])<<8 | int(payload[off+1])
		if length != len(u) {
			t.Fatalf("length prefix %d != %d", length, len(u))
		}
		if string(payload[off+2:off+2+length]) != u {
			t.Fatalf("segment mismatch for %q", u)
		}
		off += 2 + length
	}
	if off != len(payload) {
		t.Fatalf("trailing bytes: off=%d len=%d", off, len(payload))
	}
}

func TestEncodeOption143RejectsNonHTTPS(t *testing.T) {
	for _, bad := range []string{"http://x", "ftp://x", "x"} {
		if _, err := EncodeOption143([]string{bad}); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestEncodeOption143RejectsEmptyList(t *testing.T) {
	if _, err := EncodeOption143(nil); err == nil {
		t.Fatal("expected error for empty list")
	}
	if _, err := EncodeOption143([]string{"", "   "}); err == nil {
		t.Fatal("expected error for blank-only list")
	}
}

func TestEncodeOption143RejectsNonASCII(t *testing.T) {
	if _, err := EncodeOption143([]string{"https://exámple:8080"}); err == nil {
		t.Fatal("expected error for non-ASCII URI")
	}
}

func TestEncodeOption143RejectsTooLong(t *testing.T) {
	long := "https://" + strings.Repeat("a", 0xFFFF)
	if _, err := EncodeOption143([]string{long}); err == nil {
		t.Fatal("expected error for over-length URI")
	}
}

func TestFormatIOSGroupsAndRoundTrips(t *testing.T) {
	payload, err := EncodeOption143([]string{"https://10.127.127.3:9090"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ios := FormatIOS(payload)
	decoded, err := hex.DecodeString(strings.ReplaceAll(ios, ".", ""))
	if err != nil {
		t.Fatalf("ios output not hex-decodable: %v", err)
	}
	if string(decoded) != string(payload) {
		t.Fatal("ios format did not round-trip to payload")
	}
}

func TestFormatHexPlain(t *testing.T) {
	payload, err := EncodeOption143([]string{testURL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if FormatHex(payload) != hex.EncodeToString(payload) {
		t.Fatal("hex format mismatch")
	}
}
