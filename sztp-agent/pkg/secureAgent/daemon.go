/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

package secureAgent

import (
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
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func (a *Agent) RunCommandDaemon() error {
	err := a.getBootstrapURL()
	if err != nil {
		return err
	}
	err = a.doRequestBootstrapServerOnboardingInfo()
	if err != nil {
		return err
	}
	err = a.downloadAndValidateImage()
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

func (a *Agent) doReportProgress() error {
	log.Println("[INFO] Starting the Report Progress request.")
	url := strings.Replace(a.GetBootstrapURL(), "get-bootstrapping-data", "report-progress", -1)
	a.SetProgressJson(ProgressJSON{
		IetfSztpBootstrapServerInput: struct {
			ProgressType string `json:"progress-type"`
			Message      string `json:"message"`
		}{
			ProgressType: ProgressTypeBootstrapInitiated.String(),
			Message:      "message sent via JSON",
		},
	})
	inputJson, _ := json.Marshal(a.GetProgressJson())
	res, err := a.doTLSRequest(string(inputJson), url)
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
	res, err := a.doTLSRequest(a.GetInputJSONContent(), a.GetBootstrapURL())
	if err != nil {
		log.Println("[ERROR] ", err.Error())
		return err
	}
	log.Println("[INFO] Response retrieved successfully")
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
	// TODO: conveyed-info can be either redirect-information or onboarding-information
	//		 so decode using BootstrapServerRedirectInfo or BootstrapServerOnboardingInfo
	var oi BootstrapServerOnboardingInfo
	derr := json.Unmarshal(data.Bytes, &oi)
	if derr != nil {
		return derr
	}
	res.IetfSztpBootstrapServerOutput.ConveyedInformation = string(data.Bytes)
	a.BootstrapServerOnboardingInfo = oi
	log.Println(res)
	return nil
}

func (a *Agent) downloadAndValidateImage() error {
	log.Printf("[INFO] Starting the Download Image: %v", a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.BootImage.DownloadURI)
	// Download the image from DownloadURI and save it to a file
	a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference = fmt.Sprintf("%+8d", time.Now().Unix())
	var wg sync.WaitGroup
	wg.Add(len(a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.BootImage.DownloadURI))
	for i, item := range a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.BootImage.DownloadURI {
		//goroutine to make the download concurrent
		go func(i int, url, name, prefix string) error {
			defer wg.Done()
			response, err := http.Get(url)
			if err != nil {
				return err
			}
			defer response.Body.Close()

			if response.StatusCode != 200 {
				return errors.New("Received non 200 response code")
			}
			//Create a empty file
			file, err := os.Create(ARTIFACTS_PATH + prefix + name)
			if err != nil {
				return err
			}

			size, err := io.Copy(file, response.Body)
			log.Printf("[INFO] Downloaded file: %s with size: %d", ARTIFACTS_PATH+prefix+name, size)
			log.Println("[INFO] Verify the file checksum: ", ARTIFACTS_PATH+prefix+name)
			//switch a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.BootImage.ImageVerification[i].HashAlgorithm {
			//case "sha256":
			//}

			return nil
		}(i, item, filepath.Base(item), a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference)

	}
	wg.Wait()
	return nil
}
