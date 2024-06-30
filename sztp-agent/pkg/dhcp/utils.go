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
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
)

// DHCPTestContent is a test content for DHCP Lease file
const DHCPTestContent = `lease {
	interface "eth0";
	fixed-address 10.127.127.100;
	filename "grubx64.efi";
	option subnet-mask 255.255.255.0;
	option sztp-redirect-urls "http://mymock/test";
	option dhcp-lease-time 600;
	option tftp-server-name "w.x.y.z";
	option bootfile-name "test.cfg";
	option dhcp-message-type 5;
	option dhcp-server-identifier 10.127.127.2;
	renew 1 2022/08/15 19:16:40;
	rebind 1 2022/08/15 19:20:50;
	expire 1 2022/08/15 19:22:05;
  }`

// LinesInFileContains is an Auxiliar function to get lines from file matching with the substr
func LinesInFileContains(file string, substr string) string {
	// nolint:gosec
	f, _ := os.Open(file)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, substr) {
			return line
		}
	}
	return ""
}

// ExtractfromLine is an Auxiliar function to extract a string from a line using a regex
func ExtractfromLine(line, regex string, index int) string {
	re := regexp.MustCompile(regex)
	res := re.FindAllString(line, -1)
	if len(res) == 1 {
		return ""
	}
	return re.FindAllString(line, -1)[index]
}

// CreateTempTestFile creates a temporary file with the given content
func CreateTempTestFile(file string, content string, _ bool) {
	log.Println("Creating file " + file)
	// nolint:gosec
	f, err := os.Create(file)
	if err != nil {
		log.Fatal(err)
	}

	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			log.Fatalf("Unable to close file %s: %v", f.Name(), err)
		}
	}(f)

	_, err = f.WriteString(content)
	if err != nil {
		log.Printf("Could not write to file %s: %v", f.Name(), err)
	}
}

// DeleteTempTestFile deletes a temporary file
func DeleteTempTestFile(file string) {
	log.Println("Deleting file " + file)
	err := os.RemoveAll(file)

	if err != nil {
		fmt.Println(err)
		return
	}
}
