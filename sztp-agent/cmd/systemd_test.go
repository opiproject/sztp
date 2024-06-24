package cmd

import (
	"github.com/spf13/cobra"
	"reflect"
	"testing"
)

func TestSystemdCommand(t *testing.T) {
	tests := []struct {
		name string
		want *cobra.Command
	}{
		{
			name: "TestSystemdCommand",
			want: &cobra.Command{
				Use:   "systemd",
				Short: "Create a template systemd unit file",
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
			if got := NewSystemdCommand(""); !reflect.DeepEqual(got.Commands(), tt.want.Commands()) {
				t.Errorf("NewStatusCommand() = %v, want %v", got, tt.want)
			}
		})
	}
}
