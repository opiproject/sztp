// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 Red Hat.
package cmd

import (
	"github.com/spf13/cobra"
	"reflect"
	"testing"
)

func TestNewDaemonCommand(t *testing.T) {
	tests := []struct {
		name string
		want *cobra.Command
	}{
		{
			name: "TestNewDaemonCommand",
			want: &cobra.Command{
				Use:   "daemon",
				Short: "Run the daemon command",
				RunE: func(cmd *cobra.Command, args []string) error {
					return nil
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewDaemonCommand(); !reflect.DeepEqual(got.Commands(), tt.want.Commands()) {
				t.Errorf("NewDaemonCommand() = %v, want %v", got, tt.want)
			}
		})
	}
}
