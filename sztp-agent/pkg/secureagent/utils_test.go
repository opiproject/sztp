// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 Red Hat.

// Package secureagent implements the secure agent
package secureagent

import (
	"os"
	"testing"
)

func Test_replaceQuotes(t *testing.T) {
	type args struct {
		input string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test remove Quotes",
			args: args{
				input: "mynew\"car",
			},
			want: "mynewcar",
		},
		{
			name: "Test ok without removing Quotes",
			args: args{
				input: "mynewcar",
			},
			want: "mynewcar",
		},
		{
			name: "Test ok without removing only Quotes",
			args: args{
				input: "\"",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := replaceQuotes(tt.args.input); got != tt.want {
				t.Errorf("replaceQuotes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_calculateSHA256File(t *testing.T) {
	content := []byte("temporary file's content")
	file, err := os.CreateTemp("", "example")
	if err != nil {
		t.Fatal("Failed to create file", err)
	}
	defer func() {
		_ = os.Remove(file.Name())
	}()

	if _, err := file.Write(content); err != nil {
		t.Fatal("Failed to write to file", err)
	}

	if err := file.Close(); err != nil {
		t.Fatal("Unable to close the file", err)
	}

	checksum, err := calculateSHA256File(file.Name())
	if err != nil {
		t.Fatal("Could not calculate SHA256", file.Name())
	}
	expected := "df3ae2e9b295f790e12e6cf440ffc461d4660f266b84865f14c5508cf68e6f3d"
	if checksum != expected {
		t.Errorf("Checksum did not match %s %s", checksum, expected)
	}
}
