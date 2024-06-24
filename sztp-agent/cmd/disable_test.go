// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 Red Hat.

// Package cmd implements the CLI commands
package cmd

import (
	"reflect"
	"testing"

	"github.com/spf13/cobra"
)

func TestDisableCommand(t *testing.T) {
	tests := []struct {
		name string
		want *cobra.Command
	}{
		{
			name: "TestDisableCommand",
			want: &cobra.Command{
				Use:   "disable",
				Short: "Run the disable command",
				RunE: func(_ *cobra.Command, _ []string) error {
					return nil
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Disable(); !reflect.DeepEqual(got.Commands(), tt.want.Commands()) {
				t.Errorf("Disable() = %v, want %v", got, tt.want)
			}
		})
	}
}
