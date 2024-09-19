/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// Package cmd implements the CLI commands
package cmd

import (
	"github.com/opiproject/sztp/sztp-agent/pkg/secureagent"
	"github.com/spf13/cobra"
)

//nolint:gochecknoinits
func init() {
	commands = append(commands, Disable())
}

// Disable returns the disable command
func Disable() *cobra.Command {
	var (
		bootstrapURL             string
		serialNumber             string
		dhcpLeaseFile            string
		devicePassword           string
		devicePrivateKey         string
		deviceEndEntityCert      string
		bootstrapTrustAnchorCert string
		statusFilePath           string
		resultFilePath		     string
		symLinkDir			     string
	)

	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Run the disable command",
		RunE: func(_ *cobra.Command, _ []string) error {
			client := secureagent.NewHTTPClient(bootstrapTrustAnchorCert, deviceEndEntityCert, devicePrivateKey)
			a := secureagent.NewAgent(bootstrapURL, serialNumber, dhcpLeaseFile, devicePassword, devicePrivateKey, deviceEndEntityCert, bootstrapTrustAnchorCert, statusFilePath, resultFilePath, symLinkDir, &client)
			return a.RunCommandDisable()
		},
	}

	flags := cmd.Flags()
	// TODO this options should be retrieved automatically instead of requests in the agent
	// Opened discussion to define the procedure: https://github.com/opiproject/sztp/issues/2
	flags.StringVar(&bootstrapURL, "bootstrap-url", "", "Bootstrap server URL")
	flags.StringVar(&serialNumber, "serial-number", "", "Device's serial number")
	flags.StringVar(&dhcpLeaseFile, "dhcp-lease-file", "/var/lib/dhclient/dhclient.leases", "Device's dhclient leases file")
	flags.StringVar(&devicePassword, "device-password", "", "Device's password")
	flags.StringVar(&devicePrivateKey, "device-private-key", "", "Device's private key")
	flags.StringVar(&deviceEndEntityCert, "device-end-entity-cert", "", "Device's End Entity cert")
	flags.StringVar(&bootstrapTrustAnchorCert, "bootstrap-trust-anchor-cert", "", "Bootstrap server trust anchor Cert")
	flags.StringVar(&statusFilePath, "status-file-path", "", "Status file path")
	flags.StringVar(&resultFilePath, "result-file-path", "", "Result file path")
	flags.StringVar(&symLinkDir, "sym-link-dir", "", "Sym Link Directory")

	return cmd
}
