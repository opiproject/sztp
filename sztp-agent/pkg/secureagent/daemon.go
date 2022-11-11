/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/
// Package secureAgent implements the secure agent
package secureagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/github/smimesign/ietf-cms/protocol"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	PRE  = "pre"
	POST = "post"
)

// RunCommandDaemon runs the command in the background
func (a *Agent) RunCommandDaemon() error {
	err := a.getBootstrapURL()
	if err != nil {
		return err
	}
	err = a.doRequestBootstrapServerOnboardingInfo()
	if err != nil {
		return err
	}
	// TODO: conveyed-info can be either redirect-information or onboarding-information
	err = a.downloadAndValidateImage()
	if err != nil {
		return err
	}
	err = a.copyConfigurationFile()
	if err != nil {
		return err
	}
	err = a.launchScriptsConfiguration(PRE)
	if err != nil {
		return err
	}
	err = a.launchScriptsConfiguration(POST)
	if err != nil {
		return err
	}
	return nil
}

func (a *Agent) getBootstrapURL() error {
	log.Println("[INFO] Get the Bootstrap URL from DHCP client")
	var line string
	if _, err := os.Stat(a.DhcpLeaseFile); err == nil {
		for {
			line = linesInFileContains(a.DhcpLeaseFile, SZTP_REDIRECT_URL)
			if line != "" {
				break
			}
		}
		a.SetBootstrapURL(extractfromLine(line, `(?m)[^"]*`, 1))
	} else {
		log.Printf(" File " + a.DhcpLeaseFile + " does not exist\n")
		return errors.New(" File " + a.DhcpLeaseFile + " does not exist\n")
	}
	log.Println("[INFO] Bootstrap URL retrieved successfully.")
	return nil
}

func (a *Agent) doReportProgress(s ProgressType) error {
	log.Println("[INFO] Starting the Report Progress request.")
	url := strings.ReplaceAll(a.GetBootstrapURL(), "get-bootstrapping-data", "report-progress")
	a.SetProgressJSON(ProgressJSON{
		IetfSztpBootstrapServerInput: struct {
			ProgressType string `json:"progress-type"`
			Message      string `json:"message"`
		}{
			ProgressType: s.String(),
			Message:      "message sent via JSON",
		},
	})
	inputJSON, _ := json.Marshal(a.GetProgressJSON())
	res, err := a.doTLSRequest(string(inputJSON), url, true)
	if err != nil {
		log.Println("[ERROR] ", err.Error())
		return err
	}
	log.Println(res)
	log.Println("[INFO] Response retrieved successfully")
	return nil
}
func (a *Agent) doRequestBootstrapServerOnboardingInfo() error {
	log.Println("[INFO] Starting the Request to get On-boarding Information.")
	res, err := a.doTLSRequest(a.GetInputJSONContent(), a.GetBootstrapURL(), false)
	if err != nil {
		log.Println("[ERROR] ", err.Error())
		return err
	}
	log.Println("[INFO] Response retrieved successfully")
	_ = a.doReportProgress(ProgressTypeBootstrapInitiated)
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

//nolint:funlen
func (a *Agent) downloadAndValidateImage() error {
	log.Printf("[INFO] Starting the Download Image: %v", a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.BootImage.DownloadURI)
	_ = a.doReportProgress(ProgressTypeBootImageInitiated)
	// Download the image from DownloadURI and save it to a file
	a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference = fmt.Sprintf("%8d", time.Now().Unix())
	for i, item := range a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.BootImage.DownloadURI {
		// TODO: maybe need to file download to a function in util.go
		log.Printf("[INFO] Downloading Image %v", item)
		// Create a empty file
		file, err := os.Create(ARTIFACTS_PATH + a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference + filepath.Base(item))
		if err != nil {
			return err
		}

		check := http.Client{
			CheckRedirect: func(r *http.Request, via []*http.Request) error {
				r.URL.Opaque = r.URL.Path
				return nil
			},
		}

		response, err := check.Get(item)
		if err != nil {
			return err
		}

		sizeorigin, _ := strconv.Atoi(response.Header.Get("Content-Length"))
		downloadSize := int64(sizeorigin)
		log.Printf("[INFO] Downloading the image with size: %v", downloadSize)

		if response.StatusCode != 200 {
			return errors.New("Received non 200 response code")
		}
		size, err := io.Copy(file, response.Body)
		if err != nil {
			return err
		}
		defer file.Close()
		defer response.Body.Close()

		log.Printf("[INFO] Downloaded file: %s with size: %d", ARTIFACTS_PATH+a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference+filepath.Base(item), size)
		log.Println("[INFO] Verify the file checksum: ", ARTIFACTS_PATH+a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference+filepath.Base(item))
		// TODO: maybe need to move sha calculatinos to a function in util.go
		switch a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.BootImage.ImageVerification[i].HashAlgorithm {
		case "ietf-sztp-conveyed-info:sha-256":
			f, err := os.Open(ARTIFACTS_PATH + a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference + filepath.Base(item))
			if err != nil {
				log.Panic(err)
				return err
			}
			defer f.Close()
			h := sha256.New()
			if _, err := io.Copy(h, f); err != nil {
				return err
			}
			sum := fmt.Sprintf("%x", h.Sum(nil))
			log.Println(sum)
			log.Println(strings.ReplaceAll(a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.BootImage.ImageVerification[i].HashValue, ":", ""))
			original := strings.ReplaceAll(a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.BootImage.ImageVerification[i].HashValue, ":", "")
			if sum != original {
				return errors.New("Checksum mismatch")
			}
			log.Println("[INFO] Checksum verified successfully")
			return nil
		default:
			return errors.New("Unsupported hash algorithm")
		}
	}
	return nil
}

func (a *Agent) copyConfigurationFile() error {
	log.Println("[INFO] Starting the Copy Configuration.")
	// Copy the configuration file to the device
	file, err := os.Create(ARTIFACTS_PATH + a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference + "-config")
	if err != nil {
		log.Println("[ERROR] creating the configuration file", err.Error())
		return err
	}
	defer file.Close()

	plainTest, _ := base64.StdEncoding.DecodeString(a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.Configuration)
	_, err = file.WriteString(string(plainTest))
	if err != nil {
		log.Println("[ERROR] writing the configuration file", err.Error())
		return err
	}
	err = os.Chmod(ARTIFACTS_PATH+a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference+"-config", 0744)
	if err != nil {
		log.Println("[ERROR] changing the configuration file permission", err.Error())
		return err
	}
	log.Println("[INFO] Configuration file copied successfully")
	return nil
}

func (a *Agent) launchScriptsConfiguration(typeOf string) error {
	var script, scriptName string
	var report ProgressType
	switch typeOf {
	case "post":
		script = a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.PostConfigurationScript
		scriptName = "post"
		report = ProgressTypePostScriptInitiated
	default: // pre or default
		script = a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.PreConfigurationScript
		scriptName = "pre"
		report = ProgressTypePreScriptInitiated
	}
	log.Println("[INFO] Starting the " + scriptName + "-configuration.")
	_ = a.doReportProgress(report)
	file, err := os.Create(ARTIFACTS_PATH + a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference + scriptName + "configuration.sh")
	if err != nil {
		log.Println("[ERROR] creating the "+scriptName+"-configuration script", err.Error())
		return err
	}
	defer file.Close()

	plainTest, _ := base64.StdEncoding.DecodeString(script)
	_, err = file.WriteString(string(plainTest))
	if err != nil {
		log.Println("[ERROR] writing the "+scriptName+"-configuration script", err.Error())
		return err
	}
	err = os.Chmod(ARTIFACTS_PATH+a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference+scriptName+"configuration.sh", 0755)
	if err != nil {
		log.Println("[ERROR] changing the "+scriptName+"-configuration script permission", err.Error())
		return err
	}
	log.Println("[INFO] " + scriptName + "-configuration script created successfully")
	cmd := exec.Command("/bin/sh", ARTIFACTS_PATH+a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference+scriptName+"configuration.sh") //nolint:gosec
	out, err := cmd.Output()
	if err != nil {
		log.Println("[ERROR] running the "+scriptName+"-configuration script", err.Error())
		return err
	}
	log.Println(string(out)) // remove it
	log.Println("[INFO] " + scriptName + "-Configuration script executed successfully")
	return nil
}
