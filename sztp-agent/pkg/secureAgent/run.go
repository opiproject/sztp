/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

package secureAgent

func RunCommandRun() error {
	a := NewAgent("")
	err := a.run()
	return err
}

func (a *Agent) run() error {
	return nil
}
