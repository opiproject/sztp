/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

package secureAgent

func (a *Agent) RunCommandDaemon() error {
	err := a.prepareEnvDaemon()
	err = a.configureDaemon()
	err = a.runDaemon()
	return err
}

func (a *Agent) prepareEnvDaemon() error {
	return nil
}
func (a *Agent) configureDaemon() error {
	return nil
}
func (a *Agent) runDaemon() error {
	return nil
}
