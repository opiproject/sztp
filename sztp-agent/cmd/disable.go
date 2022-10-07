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

func NewDisableCommand() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Run the disable command",
		RunE: func(cmd *cobra.Command, args []string) error {
			return secureAgent.RunCommandDisable()
		},
	}
	return cmd
}
