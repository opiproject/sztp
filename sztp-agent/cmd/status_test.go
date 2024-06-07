// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 Red Hat.

// Package cmd implements the CLI commands
package cmd

import (
	"reflect"
	"testing"

	"github.com/spf13/cobra"
)

func TestNewStatusCommand(t *testing.T) {
	tests := []struct {
		name string
		want *cobra.Command
	}{
		{
			name: "TestNewStatusCommand",
			want: &cobra.Command{
				Use:   "status",
				Short: "Run the status command",
				RunE: func(cmd *cobra.Command, args []string) error {
					return nil
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewStatusCommand(); !reflect.DeepEqual(got.Commands(), tt.want.Commands()) {
				t.Errorf("NewStatusCommand() = %v, want %v", got, tt.want)
			}
		})
	}
}
