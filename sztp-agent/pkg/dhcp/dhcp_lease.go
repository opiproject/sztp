/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// Package dhcp implements the DHCP client
package dhcp

import (
	"errors"
	"log"
	"os"
)

const sztpRedirectUrls = "sztp-redirect-urls"

// getBootstrapURLViaLeaseFile returns the sztp redirect URL via DHCP lease file
func getBootstrapURLViaLeaseFile(dhcpLeaseFile string) (string, error) {
	var line string
	if _, err := os.Stat(dhcpLeaseFile); err == nil {
		for {
			line = LinesInFileContains(dhcpLeaseFile, sztpRedirectUrls)
			if line != "" {
				break
			}
		}
		return ExtractfromLine(line, `(?m)[^"]*`, 1), nil
	}
	log.Println("[Error] File " + dhcpLeaseFile + " does not exist")
	return "", errors.New("File " + dhcpLeaseFile + " does not exist")
}
