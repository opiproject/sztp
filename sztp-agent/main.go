/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// Package main
package main

import (
	"github.com/TwiN/go-color"
	"github.com/opiproject/sztp/sztp-agent/cmd"

	"log"
)

func main() {
	if err := cmd.RootCmd().Execute(); err != nil {
		log.Fatalf(color.InRed("[ERROR]")+"%s", err.Error())
	}
}
