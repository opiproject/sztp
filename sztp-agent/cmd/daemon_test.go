// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 Red Hat.

// Package cmd implements the CLI commands
package cmd

import (
	"reflect"
	"testing"

	"github.com/spf13/cobra"
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
				RunE: func(c *cobra.Command, _ []string) error {
					err := c.Help()
					cobra.CheckErr(err)
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
