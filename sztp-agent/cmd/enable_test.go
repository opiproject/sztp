// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 Red Hat.

// Package cmd implements the CLI commands
package cmd

import (
	"reflect"
	"testing"

	"github.com/spf13/cobra"
)

func TestNewEnableCommand(t *testing.T) {
	tests := []struct {
		name string
		want *cobra.Command
	}{
		{
			name: "TestNewEnableCommand",
			want: &cobra.Command{
				Use:   "enable",
				Short: "Run the enable command",
				RunE: func(c *cobra.Command, args []string) error {
					err := c.Help()
					cobra.CheckErr(err)
					return nil
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewEnableCommand(); !reflect.DeepEqual(got.Commands(), tt.want.Commands()) {
				t.Errorf("NewEnableCommand() = %v, want %v", got, tt.want)
			}
		})
	}
}
