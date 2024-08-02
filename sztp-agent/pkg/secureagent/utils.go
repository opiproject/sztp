/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// Package secureagent implements the secure agent
package secureagent

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/go-ini/ini"
	"github.com/jaypipes/ghw"
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

// CalculateFileSHA256 computes the SHA-256 checksum of a file specified by its path.
func CalculateFileSHA256(filePath string) (string, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Create a new SHA256 hash object
	hash := sha256.New()

	// Copy the file content to the hash object
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	// Get the final SHA256 hash result
	checksum := hash.Sum(nil)

	// Convert the result to a hexadecimal string
	return fmt.Sprintf("%x", checksum), nil
}

func generateInputJSONContent() string {
	osName := ""
	osVersion := ""
	cfg, err := ini.Load(OS_RELEASE_FILE)
	if err != nil {
		log.Printf("[ERROR] Error loading os-release file: %v", err)
	} else {
		osName = cfg.Section("").Key("NAME").String()
		osVersion = cfg.Section("").Key("VERSION").String()
	}
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
