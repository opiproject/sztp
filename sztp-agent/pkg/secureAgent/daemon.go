/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

package secureAgent

import (
	"errors"
	"log"
	"os"
)

const (
	DHCLIENT_LEASE_FILE = "/var/lib/dhclient/dhclient.leases"
	SZTP_REDIRECT_URL   = "sztp-redirect-urls"
)

func (a *Agent) RunCommandDaemon() error {
	err := a.prepareEnvDaemon()
	if err != nil {
		return err
	}
	//err = a.configureDaemon()
	//err = a.runDaemon()
	return err
}

func (a *Agent) prepareEnvDaemon() error {
	log.Println("[INFO] Get the Bootstrap URL from DHCP client")

	if _, err := os.Stat(DHCLIENT_LEASE_FILE); err == nil {
		line := linesInFileContains(DHCLIENT_LEASE_FILE, SZTP_REDIRECT_URL)
		a.BootstrapURL = extractURLfromLine(line, `(?m)[^"]*`)
		log.Println(a)
	} else {
		log.Printf(" File " + DHCLIENT_LEASE_FILE + " does not exist\n")
		return errors.New(" File " + DHCLIENT_LEASE_FILE + " does not exist\n")
	}
	log.Println("[INFO] Bootstrap URL retrieved successfully")
	return nil
}
func (a *Agent) configureDaemon() error {
	return nil
}
func (a *Agent) runDaemon() error {
	return nil
}
