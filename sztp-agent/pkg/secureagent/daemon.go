/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// Package secureagent implements the secure agent
package secureagent

import (
	"log"
	"time"
)

// RunCommandDaemon runs the command in the background
func (a *Agent) RunCommandDaemon() error {
	if err := a.prepareStatus(); err != nil {
		log.Println("failed to prepare status: ", err)
		return err
	}
	_ = a.updateAndSaveStatus(StageTypeIsCompleted, true, "")
	for {
		err := a.performBootstrapSequence()
		if err != nil {
			log.Println("[ERROR] Failed to perform the bootstrap sequence: ", err.Error())
			log.Println("[INFO] Retrying in 5 seconds")
			time.Sleep(5 * time.Second)
			_ = a.updateAndSaveStatus(StageTypeIsCompleted, false, err.Error())
			continue
		}
		_ = a.updateAndSaveStatus(StageTypeIsCompleted, false, "")
		return nil
	}
}