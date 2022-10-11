/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

package secureAgent

func (a *Agent) RunCommandDisable() error {

	err := a.prepareEnvDisable()
	err = a.configureDisable()
	err = a.runDisable()
	return err
}

func (a *Agent) prepareEnvDisable() error {
	return nil
}
func (a *Agent) configureDisable() error {
	return nil
}
func (a *Agent) runDisable() error {
	return nil
}
