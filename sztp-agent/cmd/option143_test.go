/*
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Cisco Systems, Inc.
*/

package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func runOption143(args ...string) (string, error) {
	cmd := Option143()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return strings.TrimSpace(out.String()), err
}

func TestOption143DefaultColon(t *testing.T) {
	got, err := runOption143("https://10.127.127.3:8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	const want = "00:19:68:74:74:70:73:3a:2f:2f:31:30:2e:31:32:37:2e:31:32:37:2e:33:3a:38:30:38:30"
	if got != want {
		t.Fatalf("colon output mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestOption143HexFormat(t *testing.T) {
	got, err := runOption143("--format", "hex", "https://10.127.127.3:8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(got, ":") || !strings.HasPrefix(got, "0019") {
		t.Fatalf("unexpected hex output: %s", got)
	}
}

func TestOption143IOSFormat(t *testing.T) {
	got, err := runOption143("--format", "ios", "https://10.127.127.3:8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, ".") || !strings.HasPrefix(got, "0019") {
		t.Fatalf("unexpected ios output: %s", got)
	}
}

func TestOption143RejectsNonHTTPS(t *testing.T) {
	if _, err := runOption143("ftp://x:8080"); err == nil {
		t.Fatal("expected error for non-https URI")
	}
}

func TestOption143RejectsUnknownFormat(t *testing.T) {
	if _, err := runOption143("--format", "nope", "https://x:8080"); err == nil {
		t.Fatal("expected error for unknown format")
	}
}
