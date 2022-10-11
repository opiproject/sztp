/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

package secureAgent

func (a *Agent) RunCommandStatus() error {

	err := a.prepareEnvStatus()
	err = a.configureStatus()
	err = a.runStatus()
	return err
}

func (a *Agent) prepareEnvStatus() error {
	return nil
}
func (a *Agent) configureStatus() error {
	return nil
}
func (a *Agent) runStatus() error {
	return nil
}
