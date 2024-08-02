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

func TestCalculateFileSHA256(t *testing.T) {
	// Define test cases
	tests := []struct {
		name     string
		filePath string
		want     string
		wantErr  bool
	}{
		{
			name:     "Valid file",
			filePath: "testfile.txt",
			want:     "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2", // Replace with actual expected hash
			wantErr:  false,
		},
		{
			name:     "Non-existent file",
			filePath: "nonexistentfile.txt",
			want:     "",
			wantErr:  true,
		},
	}

	// Create a valid file for testing
	err := os.WriteFile("testfile.txt", []byte("test"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove("testfile.txt") // Clean up the file after tests

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CalculateFileSHA256(tt.filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("CalculateFileSHA256() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CalculateFileSHA256() = %v, want %v", got, tt.want)
			}
		})
	}
}
