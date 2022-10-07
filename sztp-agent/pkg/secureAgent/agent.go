/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

package secureAgent

type Agent struct {
	ConfigURL string
	//TBD the rest of fields
}

func NewAgent(configURL string) *Agent {
	return &Agent{ConfigURL: configURL}
}

func (a Agent) GetConfigURL() string {
	return a.ConfigURL
}
