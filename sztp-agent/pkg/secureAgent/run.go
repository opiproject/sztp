/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

package secureAgent

func (a *Agent) RunCommand() error {

	err := a.prepareEnv()
	err = a.configure()
	err = a.run()
	return err
}

func (a *Agent) prepareEnv() error {
	return nil
}
func (a *Agent) configure() error {
	return nil
}
func (a *Agent) run() error {
	return nil
}
