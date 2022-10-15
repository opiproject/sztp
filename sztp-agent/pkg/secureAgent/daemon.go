/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

package secureAgent

import (
	"encoding/base64"
	"errors"
	"log"
	"os"
)

func (a *Agent) RunCommandDaemon() error {
	err := a.getBootstrapURL()
	if err != nil {
		return err
	}
	err = a.doRequestBootstrapServer()
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
func (a *Agent) doRequestBootstrapServer() error {

	log.Println("[INFO] Starting the Request to get On-boarding Information.")
	res, err := a.doTLSRequestToBootstrap()
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
	res.IetfSztpBootstrapServerOutput.ConveyedInformation = string(newVal)
	log.Println(res)
	return nil
}
