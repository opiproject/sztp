// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 Red Hat.
package cmd

import (
	"reflect"
	"testing"

	"github.com/spf13/cobra"
)

func TestNewDisableCommand(t *testing.T) {
	tests := []struct {
		name string
		want *cobra.Command
	}{
		{
			name: "TestNewDisableCommand",
			want: &cobra.Command{
				Use:   "disable",
				Short: "Run the disable command",
				RunE: func(cmd *cobra.Command, args []string) error {
					return nil
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewDisableCommand(); !reflect.DeepEqual(got.Commands(), tt.want.Commands()) {
				t.Errorf("NewDisableCommand() = %v, want %v", got, tt.want)
			}
		})
	}
}
