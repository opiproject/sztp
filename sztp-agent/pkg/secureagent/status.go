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

const (
    statusFilePath = "/var/lib/sztp/status.json"
    resultFilePath = "/var/lib/sztp/result.json"
    symlinkDir = "/run/sztp"
)

// Status represents the structure of status.json
// Status represents the structure of status.json
type Status struct {
    Init            StageStatus `json:"init"`
    DownloadingFile StageStatus `json:"downloading-file"`
    WaitingDHCP     string      `json:"waiting-dhcp"`
    PendingReboot   StageStatus `json:"pending-reboot"`
    IsCompleted     StageStatus `json:"is-completed"`
    DataSource      string      `json:"datasource"`
    Stage           string      `json:"stage"`
}

// Result represents the structure of result.json
type Result struct {
    DataSource string   `json:"datasource"`
    Errors     []string `json:"errors"`
}

// StageStatus holds the status for each stage of onboarding
type StageStatus struct {
    Errors []string `json:"errors"`
    Start  float64  `json:"start"`
    End    float64  `json:"end"`
}

// LoadStatusFile loads the current status.json from the filesystem.
func LoadStatusFile() (*Status, error) {
    file, err := os.ReadFile(statusFilePath)
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

// UpdateAndSaveStatus updates the specific part of the status object based on the current stage.
func UpdateAndSaveStatus(stage string, isStart bool, errMsg string) error {
    status, err := LoadStatusFile()
    if err != nil {
        fmt.Println("Creating a new status file.")
        status = &Status{
            DataSource: "ds",
            Stage:      "",
        }
    }

    now := float64(time.Now().Unix())
    switch stage {
    case "init":
        if isStart {
            status.Init.Start = now
            status.Init.End = 0
        } else {
            status.Init.End = now
            if errMsg != "" {
                status.Init.Errors = append(status.Init.Errors, errMsg)
            }
        }
    case "downloading-file":
        if isStart {
            status.DownloadingFile.Start = now
            status.DownloadingFile.End = 0
        } else {
            status.DownloadingFile.End = now
            if errMsg != "" {
                status.DownloadingFile.Errors = append(status.DownloadingFile.Errors, errMsg)
            }
        }
    case "waiting-dhcp":
        if isStart {
            status.WaitingDHCP = "in-progress"
        } else {
            status.WaitingDHCP = "completed"
        }
    case "pending-reboot":
        if isStart {
            status.PendingReboot.Start = now
            status.PendingReboot.End = 0
        } else {
            status.PendingReboot.End = now
            if errMsg != "" {
                status.PendingReboot.Errors = append(status.PendingReboot.Errors, errMsg)
            }
        }
    case "is-completed":
        if isStart {
            status.IsCompleted.Start = now
            status.IsCompleted.End = 0
        } else {
            status.IsCompleted.End = now
            if errMsg != "" {
                status.IsCompleted.Errors = append(status.IsCompleted.Errors, errMsg)
            }
        }
    }

    // Update the current stage
    if isStart {
        status.Stage = stage
    } else {
        status.Stage = ""
    }

    tempPath := statusFilePath + ".tmp"
    file, err := os.Create(tempPath)
    if err != nil {
        return err
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    if err := encoder.Encode(status); err != nil {
        return err
    }

    // Atomic move of temp file to replace the original.
    return os.Rename(tempPath, statusFilePath)
}

// SaveResultFile writes the result.json file after provisioning is complete.
func SaveResultFile(result *Result) error {
	tempPath := resultFilePath + ".tmp"
	file, err := os.Create(tempPath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(result); err != nil {
		return err
	}

	// Atomic move of temp file to replace the original.
	return os.Rename(tempPath, resultFilePath)
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
	if err := a.prepareStatus(); err != nil {
		return err
	}
	log.Println("RunCommandStatus")
	return nil
}

func (a *Agent) prepareStatus() error {
	log.Println("prepareStatus")

	// Ensure /run/sztp directory exists
	if err := EnsureDirExists(symlinkDir); err != nil {
		fmt.Printf("Failed to create directory %s: %v\n", symlinkDir, err)
		return err
	}

	// Ensure files are created
    if err := EnsureFileExists(statusFilePath); err != nil {
        return err
    }
    if err := EnsureFileExists(resultFilePath); err != nil {
        return err
    }

    // Define symlink paths
    statusSymlinkPath := filepath.Join(symlinkDir, "status.json")
    resultSymlinkPath := filepath.Join(symlinkDir, "result.json")

    // Create symlinks for status.json and result.json
    if err := CreateSymlink(statusFilePath, statusSymlinkPath); err != nil {
        fmt.Printf("Failed to create symlink for status.json: %v\n", err)
        return err
    }
    if err := CreateSymlink(resultFilePath, resultSymlinkPath); err != nil {
        fmt.Printf("Failed to create symlink for result.json: %v\n", err)
        return err
    }

    fmt.Println("Symlinks created successfully.")

    // Update the status file
    if err := UpdateAndSaveStatus("init", true, ""); err != nil {
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
