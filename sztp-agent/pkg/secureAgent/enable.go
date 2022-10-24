/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/
// Package secureAgent implements the secure agent
package secureAgent

// RunCommandEnable runs the command in the background
func (a *Agent) RunCommandEnable() error {

	err := a.prepareEnvEnable()
	err = a.configureEnable()
	err = a.runEnable()
	return err
}

func (a *Agent) prepareEnvEnable() error {
	return nil
}
func (a *Agent) configureEnable() error {
	return nil
}
func (a *Agent) runEnable() error {
	return nil
}
