/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

package secureAgent

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

const (
	DHCLIENT_LEASE_FILE = "/var/lib/dhclient/dhclient.leases"
	SZTP_REDIRECT_URL   = "sztp-redirect-urls"
)

type BootstrapServerPostOutput struct {
	IetfSztpBootstrapServerOutput struct {
		ConveyedInformation string `json:"conveyed-information"`
	} `json:"ietf-sztp-bootstrap-server:output"`
}

func (a *Agent) RunCommandDaemon() error {
	return a.runDaemon()
}

func (a *Agent) runDaemon() error {
	log.Println("[INFO] Get the Bootstrap URL from DHCP client")
	var line string
	if _, err := os.Stat(DHCLIENT_LEASE_FILE); err == nil {
		for {
			line = linesInFileContains(DHCLIENT_LEASE_FILE, SZTP_REDIRECT_URL)
			if line != "" {
				break
			}
		}
		a.BootstrapURL = extractURLfromLine(line, `(?m)[^"]*`)
		log.Println(a)
	} else {
		log.Printf(" File " + DHCLIENT_LEASE_FILE + " does not exist\n")
		return errors.New(" File " + DHCLIENT_LEASE_FILE + " does not exist\n")
	}
	log.Println("[INFO] Bootstrap URL retrieved successfully")
	return nil
}

func (a *Agent) doRequestMutualTLS() {
	body := strings.NewReader(`/tmp/input.json`)
	r, err := http.NewRequest(http.MethodPost, a.BootstrapURL, body)
	if err != nil {
		panic(err)
	}
	r.SetBasicAuth("my-serial-number", "my-secret")
	r.Header.Add("Content-Type", "Content-Type:application/yang-data+json")

	caCert, _ := ioutil.ReadFile(a.BootstrapTrustAnchorCert)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, _ := tls.LoadX509KeyPair(a.DeviceEndEntityCert, a.DevicePrivateKey)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}

	res, err := client.Do(r)
	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	post := &BootstrapServerPostOutput{}
	derr := json.NewDecoder(res.Body).Decode(post)
	if derr != nil {
		panic(derr)
	}

	if res.StatusCode != http.StatusCreated {
		panic(res.Status)
	}
}
