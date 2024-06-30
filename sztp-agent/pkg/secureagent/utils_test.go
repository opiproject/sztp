// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 Red Hat.

// Package secureagent implements the secure agent
package secureagent

import (
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
