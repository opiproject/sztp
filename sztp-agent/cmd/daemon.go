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
	"net/url"
	"os"

	"github.com/opiproject/sztp/sztp-agent/pkg/secureagent"
	"github.com/spf13/cobra"
)

//nolint:gochecknoinits
func init() {
	commands = append(commands, Daemon())
}

// Daemon returns the daemon command
func Daemon() *cobra.Command {
	var (
		bootstrapURL             string
		serialNumber             string
		dhcpLeaseFile            string
		devicePassword           string
		devicePrivateKey         string
		deviceEndEntityCert      string
		bootstrapTrustAnchorCert string
		statusFilePath           string
		resultFilePath           string
		symLinkDir               string
	)

	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the daemon command",
		RunE: func(_ *cobra.Command, _ []string) error {
			arrayChecker := []string{devicePrivateKey, deviceEndEntityCert, bootstrapTrustAnchorCert, statusFilePath, resultFilePath}
			if bootstrapURL != "" && dhcpLeaseFile != "" {
				return fmt.Errorf("'--bootstrap-url' and '--dhcp-lease-file' are mutualy exclusive")
			}
			if bootstrapURL == "" && dhcpLeaseFile == "" {
				return fmt.Errorf("'--bootstrap-url' or '--dhcp-lease-file' is required")
			}
			if dhcpLeaseFile != "" {
				arrayChecker = append(arrayChecker, dhcpLeaseFile)
			}
			if bootstrapURL != "" {
				_, err := url.ParseRequestURI(bootstrapURL)
				cobra.CheckErr(err)
			}
			for _, filePath := range arrayChecker {
				info, err := os.Stat(filePath)
				cobra.CheckErr(err)
				if info.IsDir() {
					return fmt.Errorf("must not be folder: %q", filePath)
				}
			}
			client := secureagent.NewHTTPClient(bootstrapTrustAnchorCert, deviceEndEntityCert, devicePrivateKey)
			a := secureagent.NewAgent(bootstrapURL, serialNumber, dhcpLeaseFile, devicePassword, devicePrivateKey, deviceEndEntityCert, bootstrapTrustAnchorCert, statusFilePath, resultFilePath, symLinkDir, &client)
			return a.RunCommandDaemon()
		},
	}

	flags := cmd.Flags()
	// TODO this options should be retrieved automatically instead of requests in the agent
	// Opened discussion to define the procedure: https://github.com/opiproject/sztp/issues/2
	flags.StringVar(&bootstrapURL, "bootstrap-url", "", "Bootstrap server URL. Mutually exclusive with '--dhcp-lease-file'")
	flags.StringVar(&serialNumber, "serial-number", "", "Device's serial number. If empty, discover via SMBIOS")
	flags.StringVar(&dhcpLeaseFile, "dhcp-lease-file", "", "Device's dhclient leases file. Mutually exclusive with '--bootstrap-url'")
	flags.StringVar(&devicePassword, "device-password", "my-secret", "Device's password")
	flags.StringVar(&devicePrivateKey, "device-private-key", "/certs/private_key.pem", "Device's private key")
	flags.StringVar(&deviceEndEntityCert, "device-end-entity-cert", "/certs/my_cert.pem", "Device's End Entity cert")
	flags.StringVar(&bootstrapTrustAnchorCert, "bootstrap-trust-anchor-cert", "/certs/opi.pem", "Bootstrap server trust anchor Cert")
	flags.StringVar(&statusFilePath, "status-file-path", "/var/lib/sztp/status.json", "Status file path")
	flags.StringVar(&resultFilePath, "result-file-path", "/var/lib/sztp/result.json", "Result file path")
	flags.StringVar(&symLinkDir, "sym-link-dir", "/run/sztp", "Sym Link Directory")

	return cmd
}
