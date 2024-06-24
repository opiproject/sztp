// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 Red Hat.

// Package cmd implements the CLI commands
package cmd

import (
	"reflect"
	"testing"

	"github.com/spf13/cobra"
)

func TestEnableCommand(t *testing.T) {
	tests := []struct {
		name string
		want *cobra.Command
	}{
		{
			name: "TestEnableCommand",
			want: &cobra.Command{
				Use:   "enable",
				Short: "Run the enable command",
				RunE: func(_ *cobra.Command, _ []string) error {
					return nil
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Enable(); !reflect.DeepEqual(got.Commands(), tt.want.Commands()) {
				t.Errorf("Enable() = %v, want %v", got, tt.want)
			}
		})
	}
}
