/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// Package secureagent implements the secure agent
package secureagent

import (
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
	"strconv"
	"strings"
)

// NewHTTPClient instantiate a new HTTP Client
func NewHTTPClient(bootstrapTrustAnchorCert string, deviceEndEntityCert string, devicePrivateKey string) http.Client {
	certPath := filepath.Clean(bootstrapTrustAnchorCert)
	caCert, _ := os.ReadFile(certPath)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	cert, _ := tls.LoadX509KeyPair(deviceEndEntityCert, devicePrivateKey)
	client := http.Client{
		CheckRedirect: func(r *http.Request, _ []*http.Request) error {
			r.URL.Opaque = r.URL.Path
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				//nolint:gosec
				InsecureSkipVerify: true, // TODO: remove skip verify
				RootCAs:            caCertPool,
				Certificates:       []tls.Certificate{cert},
			},
		},
	}
	return client
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

	res, err := a.HttpClient.Do(r)
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
