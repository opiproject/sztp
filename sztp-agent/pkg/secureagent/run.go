/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// Package secureagent implements the secure agent
package secureagent

import "log"

// RunCommand runs the command in the background
func (a *Agent) RunCommand() error {
	log.Println("runCommand")
	return nil
}

/*
func (a *Agent) prepareEnv() error {
	log.Println("prepareEnv")
	return nil
}
func (a *Agent) configure() error {
	log.Println("configure")
	return nil
}
func (a *Agent) run() error {
	log.Println("run")
	return nil
}
*/
