/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// Package secureagent implements the secure agent
package secureagent

import (
	"crypto/rand"
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

func saveToFile(data interface{}, filePath string) error {
	filePath = filepath.Clean(filePath)
	random, _ := rand.Prime(rand.Reader, 64)
	tempPath := fmt.Sprintf("%s.%d.tmp", filePath, random) // rand number to avoid conflicts when multiple agents are running
	tempPath = filepath.Clean(tempPath)
	file, err := os.Create(tempPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Println("[ERROR] Error when closing:", err)
		}
	}()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(data); err != nil {
		return err
	}

	// Atomic move of temp file to replace the original.
	if err := os.Rename(tempPath, filePath); err != nil {
		return fmt.Errorf("failed to rename %s to %s: %v", tempPath, filePath, err)
	}

	return nil
}

func ensureDirExists(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, 0750) // Create the directory with appropriate permissions
		if err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}
	return nil
}

func ensureFileExists(filePath string) error {
	dir := filepath.Dir(filePath)
	if err := ensureDirExists(dir); err != nil {
		return err
	}

	fmt.Printf("Checking if file %s exists...\n", filePath)

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		filePath = filepath.Clean(filePath)
		file, err := os.Create(filePath)
		if err != nil {
			return fmt.Errorf("[ERROR] failed to create file %s: %v", filePath, err)
		}
		defer func() {
			if err := file.Close(); err != nil {
				log.Println("[ERROR] Error when closing:", err)
			}
		}()
		fmt.Printf("File %s created successfully.\n", filePath)
	} else {
		fmt.Printf("File %s already exists.\n", filePath)
	}
	return nil
}

func createSymlink(targetFile, linkFile string) error {
	targetFile = filepath.Clean(targetFile)
	linkFile = filepath.Clean(linkFile)

	linkDir := filepath.Dir(linkFile)
	if err := ensureDirExists(linkDir); err != nil {
		return err
	}

	// Check if linkFile exists and is a symlink to targetFile
	if existingTarget, err := os.Readlink(linkFile); err == nil {
		if existingTarget == targetFile {
			return nil // Symlink already points to the target -> skip creation
		}
		// Remove the existing file (even if it's a wrong symlink or regular file)
		if err := os.Remove(linkFile); err != nil {
			return err
		}
	}

	return os.Symlink(targetFile, linkFile)
}

func loadFile(filePath string, v interface{}) error {
	filePath = filepath.Clean(filePath)
	file, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(file, v)
	if err != nil {
		return err
	}
	return nil
}
