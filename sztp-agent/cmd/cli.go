package cmd

import (
	"log"
	"os"

	"github.com/TwiN/go-color"
	"github.com/spf13/cobra"
)

// commands hold a slice of all cobra commands for cli tool
var commands []*cobra.Command

// RootCmd is the main entrypoint for the cli
func RootCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "opi-sztp-agent",
		Short: "opi-sztp-agent is the agent command line interface to work with the sztp workflow",
		Run: func(cmd *cobra.Command, _ []string) {
			err := cmd.Help()
			if err != nil {
				log.Fatalf(color.InRed("[ERROR]")+"%s", err.Error())
			}
			os.Exit(1)
		},
	}

	for _, cmd := range commands {
		c.AddCommand(cmd)
	}

	return c
}
