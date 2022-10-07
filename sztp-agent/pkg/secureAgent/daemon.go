/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

package secureAgent

func RunCommandDaemon() error {
	a := NewAgent("")
	err := a.execDaemon()
	return err
}

func (a *Agent) execDaemon() error {
	return nil
}
