/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// Package secureagent implements the secure agent
package secureagent

import (
    "encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// Status represents the status of the provisioning process.
type Status struct {
    Init            StageStatus `json:"init"`
    DownloadingFile StageStatus `json:"downloading-file"` // not sure if this is needed
    PendingReboot   StageStatus `json:"pending-reboot"`
    Parsing         StageStatus `json:"parsing"`
    BootImage       StageStatus `json:"boot-image"`
    PreScript       StageStatus `json:"pre-script"`
    Config          StageStatus `json:"config"`
    PostScript      StageStatus `json:"post-script"`
    Bootstrap       StageStatus `json:"bootstrap"`
    IsCompleted     StageStatus `json:"is-completed"`
    Informational   string      `json:"informational"`
    DataSource      string      `json:"datasource"`
    Stage           string      `json:"stage"`
}

type Result struct {
    DataSource string   `json:"dat asource"`
    Errors     []string `json:"errors"`
}

type StageStatus struct {
    Errors []string `json:"errors"`
    Start  float64  `json:"start"`
    End    float64  `json:"end"`
}

// LoadStatusFile loads the current status.json from the filesystem.
func (a *Agent) loadStatusFile() (*Status, error) {
    file, err := os.ReadFile(a.GetStatusFilePath())
    if err != nil {
        return nil, err
    }
    var status Status
    err = json.Unmarshal(file, &status)
    if err != nil {
        return nil, err
    }
    return &status, nil
}

func (a *Agent) UpdateAndSaveStatus(stage string, isStart bool, errMsg string) error {
	status, err := a.loadStatusFile()
	if err != nil {
		fmt.Println("Creating a new status file.")
		status = a.createNewStatus()
	}

	if err := a.updateStageStatus(status, stage, isStart, errMsg); err != nil {
		return err
	}

	return a.saveStatus(status)
}

// createNewStatus initializes a new Status object when status.json doesn't exist.
func (a *Agent) createNewStatus() *Status {
	return &Status{
		DataSource: "ds",
		Stage:      "",
	}
}

// updateStageStatus updates the status object for a specific stage.
func (a *Agent) updateStageStatus(status *Status, stage string, isStart bool, errMsg string) error {
	now := float64(time.Now().Unix())

	switch stage {
	case "init":
		updateStage(&status.Init, isStart, now, errMsg)
	case "downloading-file":
		updateStage(&status.DownloadingFile, isStart, now, errMsg)
	case "pending-reboot":
		updateStage(&status.PendingReboot, isStart, now, errMsg)
	case "is-completed":
		updateStage(&status.IsCompleted, isStart, now, errMsg)
	case "parsing":
		updateStage(&status.Parsing, isStart, now, errMsg)
	case "boot-image":
		updateStage(&status.BootImage, isStart, now, errMsg)
	case "pre-script":
		updateStage(&status.PreScript, isStart, now, errMsg)
	case "config":
		updateStage(&status.Config, isStart, now, errMsg)
	case "post-script":
		updateStage(&status.PostScript, isStart, now, errMsg)
	case "bootstrap":
		updateStage(&status.Bootstrap, isStart, now, errMsg)

	default:
		return fmt.Errorf("unknown stage: %s", stage)
	}

	// Update the current stage
	if isStart {
		status.Stage = stage
	} else {
		status.Stage = ""
	}

	return nil
}

func updateStage(stageStatus *StageStatus, isStart bool, now float64, errMsg string) {
	if isStart {
		stageStatus.Start = now
		stageStatus.End = 0
	} else {
		stageStatus.End = now
		if errMsg != "" {
			stageStatus.Errors = append(stageStatus.Errors, errMsg)
		}
	}
}

// SaveStatusToFile saves the Status object to the status.json file.
func (a *Agent) saveStatus(status *Status) error {
	return saveToFile(status, a.GetStatusFilePath())
}

// SaveResultFile saves the Result object to the result.json file.
func (a *Agent) saveResult(result *Result) error {
	return saveToFile(result, a.GetResultFilePath())
}

// EnsureDirExists checks if a directory exists, and creates it if it doesn't.
func EnsureDirExists(dir string) error {
    if _, err := os.Stat(dir); os.IsNotExist(err) {
        err := os.MkdirAll(dir, 0755) // Create the directory with appropriate permissions
        if err != nil {
            return fmt.Errorf("failed to create directory %s: %v", dir, err)
        }
    }
    return nil
}

// EnsureFile ensures that a file exists; creates it if it does not.
func EnsureFileExists(filePath string) error {
    // Ensure the directory exists
    dir := filepath.Dir(filePath)
    if err := EnsureDirExists(dir); err != nil {
        return err
    }

    // Check if the file already exists
    if _, err := os.Stat(filePath); os.IsNotExist(err) {
        // File does not exist, create it
        file, err := os.Create(filePath)
        if err != nil {
            return fmt.Errorf("failed to create file %s: %v", filePath, err)
        }
        defer file.Close()
        fmt.Printf("File %s created successfully.\n", filePath)
    } else {
        fmt.Printf("File %s already exists.\n", filePath)
    }
    return nil
}

// CreateSymlink creates a symlink for a file from target to link location.
func CreateSymlink(targetFile, linkFile string) error {
    // Ensure the directory for the symlink exists
    linkDir := filepath.Dir(linkFile)
    if err := EnsureDirExists(linkDir); err != nil {
        return err
    }

    // Remove any existing symlink
    if _, err := os.Lstat(linkFile); err == nil {
        os.Remove(linkFile)
    }

    // Create a new symlink
    return os.Symlink(targetFile, linkFile)
}

// RunCommandStatus runs the command in the background
func (a *Agent) RunCommandStatus() error {
	log.Println("RunCommandStatus")
    // read the status file and print the status in command line
    status, err := a.loadStatusFile()
    if err != nil {
        log.Println("failed to load status file: ", err)
        return err
    }
    fmt.Printf("Current status: %+v\n", status)
	return nil
}

func (a *Agent) PrepareStatus() error {
	log.Println("prepareStatus")

	// Ensure /run/sztp directory exists
	if err := EnsureDirExists(a.GetSymLinkDir()); err != nil {
		fmt.Printf("Failed to create directory %s: %v\n", a.GetSymLinkDir(), err)
		return err
	}

    if err := EnsureFileExists(a.GetStatusFilePath()); err != nil {
        return err
    }
    if err := EnsureFileExists(a.GetResultFilePath()); err != nil {
        return err
    }

    statusSymlinkPath := filepath.Join(a.GetSymLinkDir(), "status.json")
    resultSymlinkPath := filepath.Join(a.GetSymLinkDir(), "result.json")

    // Create symlinks for status.json and result.json
    if err := CreateSymlink(a.GetStatusFilePath(), statusSymlinkPath); err != nil {
        fmt.Printf("Failed to create symlink for status.json: %v\n", err)
        return err
    }
    if err := CreateSymlink(a.GetResultFilePath(), resultSymlinkPath); err != nil {
        fmt.Printf("Failed to create symlink for result.json: %v\n", err)
        return err
    }

    fmt.Println("Symlinks created successfully.")

    if err := a.UpdateAndSaveStatus("init", true, ""); err != nil {
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
