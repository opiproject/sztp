/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

package secureAgent

func RunCommandDisable() error {
	a := NewAgent("")
	err := a.execDisable()
	return err
}

func (a *Agent) execDisable() error {
	return nil
}
