package cmd

import (
	"github.com/opiproject/sztp/sztp-agent/pkg/secureagent"
	"github.com/spf13/cobra"
)

// NewSystemdCommand NewEnableCommand returns the enable command
func NewSystemdCommand() *cobra.Command {
	var (
		path    string
		options string
	)

	cmd := &cobra.Command{
		Use:   "systemd",
		Short: "Create a templated systemd unit file for sztp-agent",
		RunE: func(c *cobra.Command, _ []string) error {
			err := secureagent.CreateUnitFile(options, path)
			return err
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&path, "path", "p", "/etc/systemd/system",
		"Path for unit file to be created")
	flags.StringVarP(&options, "options", "o", "",
		"sztp-agent args/flags to add into the unit file")
	return cmd
}
