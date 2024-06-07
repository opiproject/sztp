/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// Package main
package main

import (
	"github.com/TwiN/go-color"
	"github.com/opiproject/sztp/sztp-agent/cmd"

	"log"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	command := newCommand()
	if err := command.Execute(); err != nil {
		log.Fatalf(color.InRed("[ERROR]")+"%s", err.Error())
		os.Exit(-1)
	}
}

func newCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "opi-sztp-agent",
		Short: "opi-sztp-agent is the agent command line interface to work with the sztp workflow",
		Run: func(cmd *cobra.Command, args []string) {
			err := cmd.Help()
			if err != nil {
				log.Fatalf(color.InRed("[ERROR]")+"%s", err.Error())
				os.Exit(1)
			}
			os.Exit(1)
		},
	}

	c.AddCommand(cmd.NewDaemonCommand())
	c.AddCommand(cmd.NewStatusCommand())
	c.AddCommand(cmd.NewEnableCommand())
	c.AddCommand(cmd.NewDisableCommand())

	return c
}
