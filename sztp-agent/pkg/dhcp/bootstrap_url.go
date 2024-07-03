/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// Package dhcp implements the DHCP client
package dhcp

import "log"

// GetBootstrapURL returns the bootstrap URL
func GetBootstrapURL(dhcpLeaseFile string) ([]string, error) {
	url, err := getBootstrapURLViaLeaseFile(dhcpLeaseFile)
	if err == nil {
		return []string{url}, nil
	}
	log.Println("[INFO] Trying to get the URL from NetworkManager")
	urls, err := getBootstrapURLViaNetworkManager()
	if err == nil {
		return urls, nil
	}
	return nil, err
}
