/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// Package secureagent implements the secure agent
package secureagent

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/jaypipes/ghw"
	"github.com/opiproject/sztp/sztp-agent/pkg/dhcp"
)

// GetSerialNumber returns the serial number of the device
func GetSerialNumber(givenSerialNumber string) string {
	if givenSerialNumber != "" {
		log.Println("[INFO] Using user provides serial number: " + givenSerialNumber)
		return givenSerialNumber
	}
	serialNumber := ""
	product, err := ghw.Product()
	if err != nil {
		log.Printf("[ERROR] Error getting products info: %v", err)
	} else {
		serialNumber = product.SerialNumber
	}
	log.Println("[None] Using discovered serial number: " + serialNumber)
	return serialNumber
}

func generateInputJSONContent() string {
	osName := replaceQuotes(strings.Split(dhcp.LinesInFileContains(OS_RELEASE_FILE, "NAME"), "=")[1])
	osVersion := replaceQuotes(strings.Split(dhcp.LinesInFileContains(OS_RELEASE_FILE, "VERSION"), "=")[1])
	hwModel := ""
	baseboard, err := ghw.Baseboard()
	if err != nil {
		log.Printf("[ERROR] Error getting baseboard info: %v", err)
	} else {
		hwModel = baseboard.Product
	}
	var input InputJSON
	input.IetfSztpBootstrapServerInput.HwModel = hwModel
	input.IetfSztpBootstrapServerInput.OsName = osName
	input.IetfSztpBootstrapServerInput.OsVersion = osVersion
	input.IetfSztpBootstrapServerInput.Nonce = ""
	inputJSON, _ := json.Marshal(input)
	return string(inputJSON)
}

func replaceQuotes(input string) string {
	return strings.ReplaceAll(input, "\"", "")
}
