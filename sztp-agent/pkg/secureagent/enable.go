/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/
// Package secureAgent implements the secure agent
package secureagent

import "log"

// RunCommandEnable runs the command in the background
func (a *Agent) RunCommandEnable() error {
	log.Println("RunCommandEnable")
	return nil
}

/*
func (a *Agent) prepareEnvEnable() error {
	log.Println("prepareEnvEnable")
	return nil
}
func (a *Agent) configureEnable() error {
	log.Println("configureEnable")
	return nil
}
func (a *Agent) runEnable() error {
	log.Println("runEnable")
	return nil
}
*/
