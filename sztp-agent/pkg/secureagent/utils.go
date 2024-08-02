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
	"path/filepath"
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

func calculateSHA256File(filePath string) (string, error) {
	cleanPath := filepath.Clean(filePath)
	f, err := os.Open(cleanPath)
	if err != nil {
		log.Panic(err)
		return "", err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Println("[ERROR] Error when closing:", err)
		}
	}()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	checkSum := fmt.Sprintf("%x", h.Sum(nil))
	return checkSum, nil
}
