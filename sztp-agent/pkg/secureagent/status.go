/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/
// Package secureAgent implements the secure agent
package secureagent

import "log"

// RunCommandStatus runs the command in the background
func (a *Agent) RunCommandStatus() error {
	log.Println("RunCommandStatus")
	return nil
}

/*
func (a *Agent) prepareEnvStatus() error {
	log.Println("prepareEnvStatus")
	return nil
}
func (a *Agent) configureStatus() error {
	log.Println("configureStatus")
	return nil
}
func (a *Agent) runStatus() error {
	log.Println("runStatus")
	return nil
}
*/
