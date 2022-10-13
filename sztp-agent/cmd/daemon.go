/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

package cmd

import (
	"github.com/opiproject/sztp/sztp-agent/pkg/secureAgent"
	"github.com/spf13/cobra"
)

func NewDaemonCommand() *cobra.Command {
	var (
		bootstrapURL             string
		serialNumber             string
		devicePassword           string
		devicePrivateKey         string
		deviceEndEntityCert      string
		bootstrapTrustAnchorCert string
	)

	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the daemon command",
		RunE: func(cmd *cobra.Command, args []string) error {
			a := secureAgent.NewAgent(bootstrapURL, serialNumber, devicePassword, devicePrivateKey, deviceEndEntityCert, bootstrapTrustAnchorCert)
			return a.RunCommandDaemon()
		},
	}

	flags := cmd.Flags()
	//TODO this options should be retrieved automatically instead of requests in the agent
	//Opened discussion to define the procedure: https://github.com/opiproject/sztp/issues/2
	flags.StringVar(&serialNumber, "serial-number", "my-serial", "Device's serial number")
	flags.StringVar(&devicePassword, "device-password", "mysecret", "Device's password")
	flags.StringVar(&devicePrivateKey, "device-private-key", "/private_key.pem", "Device's private key")
	flags.StringVar(&deviceEndEntityCert, "device-end-entity-cert", "/my_cert.pem", "Device's End Entity cert")
	flags.StringVar(&bootstrapTrustAnchorCert, "bootstrap-trust-anchor-cert", "/opi.pem", "Bootstrap server trust anchor Cert")

	return cmd
}
