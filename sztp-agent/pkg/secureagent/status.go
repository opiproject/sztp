/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/
// nolint
// Package secureagent implements the secure agent
package secureagent

import (
	"fmt"
	"log"
	"path/filepath"
	"time"
)

type StageType int64

const (
	StageTypeInit StageType = iota
	StageTypeDownloadingFile
	StageTypePendingReboot
	StageTypeParsing
	StageTypeOnboarding
	StageTypeRedirect
	StageTypeBootImage
	StageTypePreScript
	StageTypeConfig
	StageTypePostScript
	StageTypeBootstrap
	StageTypeIsCompleted
)

func (s StageType) String() string {
	switch s {
	case StageTypeInit:
		return "init"
	case StageTypeDownloadingFile:
		return "downloading-file"
	case StageTypePendingReboot:
		return "pending-reboot"
	case StageTypeParsing:
		return "parsing"
	case StageTypeOnboarding:
		return "onboarding"
	case StageTypeRedirect:
		return "redirect"
	case StageTypeBootImage:
		return "boot-image"
	case StageTypePreScript:
		return "pre-script"
	case StageTypeConfig:
		return "config"
	case StageTypePostScript:
		return "post-script"
	case StageTypeBootstrap:
		return "bootstrap"
	case StageTypeIsCompleted:
		return "is-completed"
	default:
		return "unknown"
	}
}

// Status represents the status of the provisioning process.
type Status struct {
	Init            StageStatus `json:"init"`
	DownloadingFile StageStatus `json:"downloading-file"`
	PendingReboot   StageStatus `json:"pending-reboot"`
	Parsing         StageStatus `json:"parsing"`
	Onboarding      StageStatus `json:"onboarding"`
	Redirect        StageStatus `json:"redirect"`
	BootImage       StageStatus `json:"boot-image"`
	PreScript       StageStatus `json:"pre-script"`
	Config          StageStatus `json:"config"`
	PostScript      StageStatus `json:"post-script"`
	Bootstrap       StageStatus `json:"bootstrap"`
	IsCompleted     StageStatus `json:"is-completed"`
	Informational   string      `json:"informational"`
	Stage           string      `json:"stage"`
}

// Result represents the result of the provisioning process.
type Result struct {
	Errors []string `json:"errors"`
}

// StageStatus represents the status of a specific stage.
type StageStatus struct {
	Errors []string `json:"errors"`
	Start  float64  `json:"start"`
	End    float64  `json:"end"`
}

func (a *Agent) getCurrStatus() (*Status, error) {
	var status Status
	err := loadFile(a.GetStatusFilePath(), &status)
	if err != nil {
		return nil, err
	}
	return &status, nil
}

func (a *Agent) getCurrResult() (*Result, error) {
	var result Result
	err := loadFile(a.GetResultFilePath(), &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (a *Agent) createNewStatus() *Status {
	return &Status{
		Stage:       "",
		IsCompleted: StageStatus{},
	}
}

// updateAndSaveStatus updates the status object for a specific stage and saves it to the status.json file.
func (a *Agent) updateAndSaveStatus(s StageType, isStart bool, errMsg string) error {
	status, err := a.getCurrStatus()
	if err != nil {
		fmt.Println("Creating a new status file.")
		status = a.createNewStatus()
	}

	err = a.updateStageStatus(status, s, isStart, errMsg)
	if err != nil {
		return err
	}

	return a.saveStatus(status)
}

// updateStageStatus updates the status object for a specific stage.
func (a *Agent) updateStageStatus(status *Status, stageType StageType, isStart bool, errMsg string) error {
	now := float64(time.Now().Unix())
	stage := stageType.String()

	switch stageType {
	case StageTypeInit:
		a.updateStage(&status.Init, isStart, now, errMsg)
	case StageTypeDownloadingFile:
		a.updateStage(&status.DownloadingFile, isStart, now, errMsg)
	case StageTypePendingReboot:
		a.updateStage(&status.PendingReboot, isStart, now, errMsg)
	case StageTypeIsCompleted:
		a.updateStage(&status.IsCompleted, isStart, now, errMsg)
	case StageTypeParsing:
		a.updateStage(&status.Parsing, isStart, now, errMsg)
	case StageTypeOnboarding:
		a.updateStage(&status.Onboarding, isStart, now, errMsg)
	case StageTypeRedirect:
		a.updateStage(&status.Redirect, isStart, now, errMsg)
	case StageTypeBootImage:
		a.updateStage(&status.BootImage, isStart, now, errMsg)
	case StageTypePreScript:
		a.updateStage(&status.PreScript, isStart, now, errMsg)
	case StageTypeConfig:
		a.updateStage(&status.Config, isStart, now, errMsg)
	case StageTypePostScript:
		a.updateStage(&status.PostScript, isStart, now, errMsg)
	case StageTypeBootstrap:
		a.updateStage(&status.Bootstrap, isStart, now, errMsg)

	default:
		return fmt.Errorf("unknown stage: %s", stage)
	}

	// Update the current stage
	if isStart {
		status.Stage = stage + "-in-progress"
	} else {
		status.Stage = stage + "-completed"
	}

	return nil
}

func (a *Agent) updateStage(stageStatus *StageStatus, isStart bool, now float64, errMsg string) {
	if isStart {
		stageStatus.Start = now
		stageStatus.End = 0
	} else {
		stageStatus.End = now
		if errMsg != "" {
			stageStatus.Errors = append(stageStatus.Errors, errMsg)
			err := a.updateAndSaveResult(errMsg)
			if err != nil {
				fmt.Printf("Failed to update and save result: %v\n", err)
			}
		}
	}
}

func (a *Agent) saveStatus(status *Status) error {
	return saveToFile(status, a.GetStatusFilePath())
}

func (a *Agent) saveResult(result *Result) error {
	return saveToFile(result, a.GetResultFilePath())
}

func (a *Agent) updateAndSaveResult(errMsg string) error {
	result, err := a.getCurrResult()
	if err != nil {
		fmt.Println("Creating a new result file.")
		result = &Result{
			Errors: []string{},
		}
	}

	if errMsg != "" {
		result.Errors = append(result.Errors, errMsg)
	}

	return a.saveResult(result)
}

// RunCommandStatus runs the command in the background
func (a *Agent) RunCommandStatus() error {
	log.Println("RunCommandStatus")
	status, err := a.getCurrStatus()
	if err != nil {
		log.Println("failed to load status file: ", err)
		return err
	}
	fmt.Printf("Current status: %+v\n", status)
	return nil
}

func (a *Agent) prepareStatus() error {
	log.Println("prepareStatus")

	// Ensure /run/sztp directory exists
	if err := ensureDirExists(a.GetSymLinkDir()); err != nil {
		fmt.Printf("Failed to create directory %s: %v\n", a.GetSymLinkDir(), err)
		return err
	}

	fmt.Println("Status File Path", a.GetStatusFilePath())
	fmt.Println("Result File Path", a.GetResultFilePath())

	if err := ensureFileExists(a.GetStatusFilePath()); err != nil {
		return err
	}
	if err := ensureFileExists(a.GetResultFilePath()); err != nil {
		return err
	}

	statusSymlinkPath := filepath.Join(a.GetSymLinkDir(), "status.json")
	resultSymlinkPath := filepath.Join(a.GetSymLinkDir(), "result.json")

	// Create symlinks for status.json and result.json
	if err := createSymlink(a.GetStatusFilePath(), statusSymlinkPath); err != nil {
		fmt.Printf("Failed to create symlink for status.json: %v\n", err)
		return err
	}
	if err := createSymlink(a.GetResultFilePath(), resultSymlinkPath); err != nil {
		fmt.Printf("Failed to create symlink for result.json: %v\n", err)
		return err
	}

	fmt.Println("Symlinks created successfully.")

	if err := a.updateAndSaveStatus(StageTypeInit, true, ""); err != nil {
		return err
	}

	return nil
}

/*
func (a *Agent) configureStatus() error {
	log.Println("configureStatus")
	return nil
}
func (a *Agent) runStatus() error {
	log.Println("runStatus")
	return nil
}
*/
