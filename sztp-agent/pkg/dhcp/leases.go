/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// Package dhcp implements the DHCP client
package dhcp

import (
	"bufio"
	"log"
	"os"
	"regexp"
	"strings"
)

// GetBootstrapURLsViaLeaseFile retrieves the Bootstrap URL from a DHCP lease file.
//
// Parameters:
// - leaseFile: the path to the DHCP lease file.
// - key: the key used to retrieve the Bootstrap URL.
//
// Returns:
// - []string: a slice of Bootstrap URLs.
// - error: an error if the file cannot be read or the key is not found.
func GetBootstrapURLsViaLeaseFile(leaseFile, key string) ([]string, error) {
	// nolint:gosec
	file, err := os.Open(leaseFile)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Println("[ERROR] Error when closing:", err)
		}
	}()

	var sztpRedirectURLs []string
	scanner := bufio.NewScanner(file)
	re := regexp.MustCompile(`(?m)[^"]*`)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, key) {
			url := re.FindAllString(line, -1)
			if len(url) == 1 {
				continue
			}
			sztpRedirectURLs = append(sztpRedirectURLs, url[1])
		}
	}

	return sztpRedirectURLs, nil
}
