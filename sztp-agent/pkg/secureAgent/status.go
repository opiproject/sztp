/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

package secureAgent

func RunCommandStatus() error {
	a := NewAgent("")
	err := a.execStatus()
	return err
}

func (a *Agent) execStatus() error {
	return nil
}
