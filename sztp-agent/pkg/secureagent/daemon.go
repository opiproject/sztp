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
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"reflect"
	"time"

	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/opiproject/sztp/sztp-agent/pkg/dhcp"
)

const (
	// PRE nolint:var-naming
	PRE = "pre"
	// POST nolint:var-naming
	POST = "post"
)

// RunCommandDaemon runs the command in the background
func (a *Agent) RunCommandDaemon() error {
	for {
		err := a.performBootstrapSequence()
		if err != nil {
			log.Println("[ERROR] Failed to perform the bootstrap sequence: ", err.Error())
			log.Println("[INFO] Retrying in 5 seconds")
			time.Sleep(5 * time.Second)
			continue
		}
		return nil
	}
}

func (a *Agent) performBootstrapSequence() error {
	var err error
	err = a.discoverBootstrapURLs()
	if err != nil {
		return err
	}
	var hasErrorOccurred bool
	urls := a.GetBootstrapURL()
	log.Println("[INFO] Performing the Bootstrap Sequence on each URL")
	for _, url := range urls {
		urlCopy := url // found no other way to escape golangci-lint
		err = a.doRequestBootstrapServerOnboardingInfo(&urlCopy)
		if err != nil {
			log.Println("[ERROR] ", err.Error())
			hasErrorOccurred = true
			continue
		}
		err = a.doHandleBootstrapRedirect(&urlCopy)
		if err != nil {
			log.Println("[ERROR] ", err.Error())
			hasErrorOccurred = true
			continue
		}
		err = a.downloadAndValidateImage(&urlCopy)
		if err != nil {
			log.Println("[ERROR] ", err.Error())
			hasErrorOccurred = true
			continue
		}
		err = a.copyConfigurationFile(&urlCopy)
		if err != nil {
			log.Println("[ERROR] ", err.Error())
			hasErrorOccurred = true
			continue
		}
		err = a.launchScriptsConfiguration(PRE, &urlCopy)
		if err != nil {
			log.Println("[ERROR] ", err.Error())
			hasErrorOccurred = true
			continue
		}
		err = a.launchScriptsConfiguration(POST, &urlCopy)
		if err != nil {
			log.Println("[ERROR] ", err.Error())
			hasErrorOccurred = true
			continue
		}
		_ = a.doReportProgress(ProgressTypeBootstrapComplete, "Bootstrap Complete", &urlCopy)
	}

	if hasErrorOccurred {
		return errors.New("error occurred during bootstrap sequence")
	}

	return nil
}

func (a *Agent) discoverBootstrapURLs() error {
	log.Println("[INFO] Discovering the Bootstrap URL")
	if a.InputBootstrapURL != "" {
		log.Println("[INFO] User gave us the Bootstrap URL: " + a.InputBootstrapURL)
		a.SetBootstrapURL([]string{a.InputBootstrapURL})
		log.Println("[INFO] Bootstrap URL retrieved successfully: ", a.GetBootstrapURL())
		return nil
	}
	if a.DhcpLeaseFile != "" {
		log.Println("[INFO] User gave us the DHCP Lease File: " + a.DhcpLeaseFile)
		urls, err := dhcp.GetBootstrapURLsViaLeaseFile(a.DhcpLeaseFile, dhcp.SZTP_REDIRECT_URLs)
		if err != nil {
			return err
		}
		a.SetBootstrapURL(urls)
		log.Println("[INFO] Bootstrap URL retrieved successfully: ", a.GetBootstrapURL())
		return nil
	}
	log.Println("[INFO] User gave us nothing, discover the Bootstrap URL from Network Manager via dbus")
	urls, err := dhcp.GetBootstrapURLsViaNetworkManager()
	if err != nil {
		log.Println("[ERROR] ", err.Error())
		return err
	}
	// TODO: get from networkd as well

	if urls == nil {
		return errors.New("no bootstrap was URL found")
	}
	a.SetBootstrapURL(urls)
	log.Println("[INFO] Bootstrap URL retrieved successfully: ")
	log.Println(a.GetBootstrapURL())
	return nil
}

func (a *Agent) doHandleBootstrapRedirect(bootstrapURL *string) error {
	if reflect.ValueOf(a.BootstrapServerRedirectInfo).IsZero() {
		return nil
	}

	log.Println("[INFO] Go Re-direct instead of On-boarding, processing...")

	// TODO: BootstrapServer can be an array
	// TODO: do not ignore BootstrapServer[0].TrustAnchor
	addr := a.BootstrapServerRedirectInfo.IetfSztpConveyedInfoRedirectInformation.BootstrapServer[0].Address
	port := a.BootstrapServerRedirectInfo.IetfSztpConveyedInfoRedirectInformation.BootstrapServer[0].Port

	if addr == "" {
		return errors.New("invalid redirect address")
	}
	if port <= 0 {
		return errors.New("invalid port")
	}
	// Change URL to point to new redirect IP and PORT
	u, err := url.Parse(*bootstrapURL)
	if err != nil {
		return err
	}
	u.Host = fmt.Sprintf("%s:%d", addr, port)
	*bootstrapURL = u.String()

	// Request onboard info again (with new URL now)
	return a.doRequestBootstrapServerOnboardingInfo(bootstrapURL)
}

func (a *Agent) doRequestBootstrapServerOnboardingInfo(bootstrapURL *string) error {
	log.Println("[INFO] Starting the Request to get On-boarding Information.")
	res, err := a.doTLSRequest(a.GetInputJSONContent(), *bootstrapURL, false)
	if err != nil {
		log.Println("[ERROR] ", err.Error())
		return err
	}
	log.Println("[INFO] Response retrieved successfully")
	_ = a.doReportProgress(ProgressTypeBootstrapInitiated, "Bootstrap Initiated", bootstrapURL)
	crypto := res.IetfSztpBootstrapServerOutput.ConveyedInformation
	newVal, err := base64.StdEncoding.DecodeString(crypto)
	if err != nil {
		return err
	}
	ci, err := protocol.ParseContentInfo(newVal)
	if err != nil {
		return err
	}
	var data asn1.RawValue
	_, kerr := asn1.Unmarshal(ci.Content.Bytes, &data)
	if kerr != nil {
		return kerr
	}
	res.IetfSztpBootstrapServerOutput.ConveyedInformation = string(data.Bytes)
	decoderoi := json.NewDecoder(bytes.NewReader(data.Bytes))
	decoderoi.DisallowUnknownFields()
	var oi BootstrapServerOnboardingInfo
	erroi := decoderoi.Decode(&oi)
	if erroi == nil {
		a.BootstrapServerOnboardingInfo = oi
		log.Printf("[INFO] The BootstrapServerOnBoardingInfo object retrieved is: %v", a.BootstrapServerOnboardingInfo)
		return nil
	}
	decoderri := json.NewDecoder(bytes.NewReader(data.Bytes))
	decoderri.DisallowUnknownFields()
	var ri BootstrapServerRedirectInfo
	errri := decoderri.Decode(&ri)
	if errri == nil {
		a.BootstrapServerRedirectInfo = ri
		log.Printf("[INFO] The BootstrapServerRedirectInfo object retrieved is: %v", a.BootstrapServerRedirectInfo)
		return nil
	}
	return errri
}
