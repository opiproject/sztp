/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/
// Package secureAgent implements the secure agent
package secureagent

import "log"

// RunCommandDisable runs the command in the background
func (a *Agent) RunCommandDisable() error {
	log.Println("RunCommandDisable")
	return nil
}

func (a *Agent) prepareEnvDisable() error {
	log.Println("prepareEnvDisable")
	return nil
}
func (a *Agent) configureDisable() error {
	log.Println("configureDisable")
	return nil
}
func (a *Agent) runDisable() error {
	log.Println("runDisable")
	return nil
}
