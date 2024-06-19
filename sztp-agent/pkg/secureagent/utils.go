/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// Package secureagent implements the secure agent
package secureagent

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/jaypipes/ghw"
)

// Auxiliar function to get lines from file matching with the substr
func linesInFileContains(file string, substr string) string {
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

func extractfromLine(line, regex string, index int) string {
	re := regexp.MustCompile(regex)
	res := re.FindAllString(line, -1)
	if len(res) == 1 {
		return ""
	}
	return re.FindAllString(line, -1)[index]
}

func (a *Agent) doTLSRequest(input string, url string, empty bool) (*BootstrapServerPostOutput, error) {
	var postResponse BootstrapServerPostOutput
	var errorResponse BootstrapServerErrorOutput

	log.Println("[DEBUG] Sending to: " + url)
	log.Println("[DEBUG] Sending input: " + input)

	body := strings.NewReader(input)
	r, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}

	r.SetBasicAuth(a.GetSerialNumber(), a.GetDevicePassword())
	r.Header.Add("Content-Type", a.GetContentTypeReq())

	caCert, _ := os.ReadFile(a.GetBootstrapTrustAnchorCert())
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	cert, _ := tls.LoadX509KeyPair(a.GetDeviceEndEntityCert(), a.GetDevicePrivateKey())

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ //nolint:gosec
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}
	res, err := client.Do(r)
	if err != nil {
		log.Println("Error doing the request", err.Error())
		return nil, err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			log.Println("Error when closing:", err)
		}
	}()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.Println("Error reading the request", err.Error())
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(bodyBytes))
	decoder.DisallowUnknownFields()
	if !empty {
		derr := decoder.Decode(&postResponse)
		if derr != nil {
			errdecoder := json.NewDecoder(bytes.NewReader(bodyBytes))
			errdecoder.DisallowUnknownFields()
			eerr := errdecoder.Decode(&errorResponse)
			if eerr != nil {
				log.Println("Received unknown response", string(bodyBytes))
				return nil, derr
			}
			return nil, errors.New("[ERROR] Expected conveyed-information" +
				", received error type=" + errorResponse.IetfRestconfErrors.Error[0].ErrorType +
				", tag=" + errorResponse.IetfRestconfErrors.Error[0].ErrorTag +
				", message=" + errorResponse.IetfRestconfErrors.Error[0].ErrorMessage)
		}
		log.Println(postResponse)
	}
	if res.StatusCode != http.StatusOK {
		return nil, errors.New("[ERROR] Status code received: " + strconv.Itoa(res.StatusCode) + " ...but status code expected: " + strconv.Itoa(http.StatusOK))
	}
	return &postResponse, nil
}

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
	osName := replaceQuotes(strings.Split(linesInFileContains(OS_RELEASE_FILE, "NAME"), "=")[1])
	osVersion := replaceQuotes(strings.Split(linesInFileContains(OS_RELEASE_FILE, "VERSION"), "=")[1])
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

type publicKey struct {
	Algorithm string
	KeyData   string
	Comment   string
}

func readSSHHostKeyPublicFiles(pattern string) []publicKey {
	results := []publicKey{}
	files, err := filepath.Glob(pattern)
	if err != nil {
		log.Printf("[ERROR] Error getting ssh host public keys file list : %v", err)
		return results
	}
	for _, f := range files {
		// nolint:gosec
		data, _ := os.ReadFile(f)
		// TODO: consider switching to https://pkg.go.dev/golang.org/x/crypto/ssh#ParseAuthorizedKey
		parts := strings.Fields(string(data))
		// [type-name] [base64-encoded-ssh-public-key] [comment]
		if len(parts) < 2 {
			log.Printf("[ERROR] Error parsing pub key, should contain at least 2 parts with spaces : %v", f)
			continue
		}
		// ignore comment for now
		results = append(results, publicKey{Algorithm: parts[0], KeyData: parts[1]})
	}
	return results
}

func replaceQuotes(input string) string {
	return strings.ReplaceAll(input, "\"", "")
}
