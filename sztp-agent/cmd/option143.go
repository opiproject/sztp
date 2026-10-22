/*
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Cisco Systems, Inc.
*/

// Package cmd implements the CLI commands
package cmd

import (
	"fmt"

	"github.com/opiproject/sztp/sztp-agent/pkg/dhcp"
	"github.com/spf13/cobra"
)

//nolint:gochecknoinits
func init() {
	commands = append(commands, Option143())
}

// Option143 returns the option143 command, which encodes https:// URIs as an
// RFC 8572 section 8.2 DHCPv4 option 143 payload for DHCP server configuration.
func Option143() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "option143 [flags] https://host:port ...",
		Short: "Encode SZTP redirect URLs as an RFC 8572 section 8.2 DHCP option 143 payload",
		RunE: func(cmd *cobra.Command, args []string) error {
			payload, err := dhcp.EncodeOption143(args)
			if err != nil {
				return err
			}
			var line string
			switch format {
			case "colon":
				line = dhcp.FormatColon(payload)
			case "hex":
				line = dhcp.FormatHex(payload)
			case "ios":
				line = dhcp.FormatIOS(payload)
			default:
				return fmt.Errorf("unknown --format %q (want colon, hex, or ios)", format)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), line)
			return err
		},
	}

	cmd.Flags().StringVar(&format, "format", "colon",
		"output format: colon (ISC dhcpd), hex, or ios (Cisco dotted-hex)")

	return cmd
}
