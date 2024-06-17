/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// Package cmd implements the CLI commands
package cmd

import (
	"fmt"
	"os"

	"github.com/opiproject/sztp/sztp-agent/pkg/secureagent"
	"github.com/spf13/cobra"
)

// NewDaemonCommand returns the daemon command
func NewDaemonCommand() *cobra.Command {
	var (
		bootstrapURL             string
		serialNumber             string
		dhcpLeaseFile            string
		devicePassword           string
		devicePrivateKey         string
		deviceEndEntityCert      string
		bootstrapTrustAnchorCert string
	)

	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the daemon command",
		RunE: func(c *cobra.Command, _ []string) error {
			arrayChecker := [4]string{dhcpLeaseFile, devicePrivateKey, deviceEndEntityCert, bootstrapTrustAnchorCert}
			for _, filePath := range arrayChecker {
				info, err := os.Stat(filePath)
				cobra.CheckErr(err)
				if info.IsDir() {
					return fmt.Errorf("must not be folder: %q", filePath)
				}
			}
			err := c.Help()
			cobra.CheckErr(err)
			a := secureagent.NewAgent(bootstrapURL, serialNumber, dhcpLeaseFile, devicePassword, devicePrivateKey, deviceEndEntityCert, bootstrapTrustAnchorCert)
			return a.RunCommandDaemon()
		},
	}

	flags := cmd.Flags()
	// TODO this options should be retrieved automatically instead of requests in the agent
	// Opened discussion to define the procedure: https://github.com/opiproject/sztp/issues/2
	flags.StringVar(&serialNumber, "serial-number", "", "Device's serial number. If empty, discover via SMBIOS")
	flags.StringVar(&dhcpLeaseFile, "dhcp-lease-file", "/var/lib/dhclient/dhclient.leases", "Device's dhclient leases file")
	flags.StringVar(&devicePassword, "device-password", "my-secret", "Device's password")
	flags.StringVar(&devicePrivateKey, "device-private-key", "/certs/private_key.pem", "Device's private key")
	flags.StringVar(&deviceEndEntityCert, "device-end-entity-cert", "/certs/my_cert.pem", "Device's End Entity cert")
	flags.StringVar(&bootstrapTrustAnchorCert, "bootstrap-trust-anchor-cert", "/certs/opi.pem", "Bootstrap server trust anchor Cert")

	return cmd
}
