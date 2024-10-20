// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 Red Hat.

// Package secureagent implements the secure agent
package secureagent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func Test_replaceQuotes(t *testing.T) {
	type args struct {
		input string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test remove Quotes",
			args: args{
				input: "mynew\"car",
			},
			want: "mynewcar",
		},
		{
			name: "Test ok without removing Quotes",
			args: args{
				input: "mynewcar",
			},
			want: "mynewcar",
		},
		{
			name: "Test ok without removing only Quotes",
			args: args{
				input: "\"",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := replaceQuotes(tt.args.input); got != tt.want {
				t.Errorf("replaceQuotes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_calculateSHA256File(t *testing.T) {
	content := []byte("temporary file's content")
	file, err := os.CreateTemp("", "example")
	if err != nil {
		t.Fatal("Failed to create file", err)
	}
	defer func() {
		_ = os.Remove(file.Name())
	}()

	if _, err := file.Write(content); err != nil {
		t.Fatal("Failed to write to file", err)
	}

	if err := file.Close(); err != nil {
		t.Fatal("Unable to close the file", err)
	}

	checksum, err := calculateSHA256File(file.Name())
	if err != nil {
		t.Fatal("Could not calculate SHA256", file.Name())
	}
	expected := "df3ae2e9b295f790e12e6cf440ffc461d4660f266b84865f14c5508cf68e6f3d"
	if checksum != expected {
		t.Errorf("Checksum did not match %s %s", checksum, expected)
	}
}

func Test_saveToFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test_save_to_file")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Fatalf("failed to remove temp directory: %v", err)
		}
	}()

	filePath := filepath.Join(tempDir, "test.json")
	data := map[string]string{"key": "value"}

	err = saveToFile(data, filePath)
	if err != nil {
		t.Fatalf("saveToFile returned an error: %v", err)
	}

	_, err = os.Stat(filePath)
	if os.IsNotExist(err) {
		t.Fatalf("file %s was not created", filePath)
	}

	filePath = filepath.Clean(filePath)
	file, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("failed to open the file: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Fatalf("failed to close the file: %v", err)
		}
	}()

	var readData map[string]string
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&readData)
	if err != nil {
		t.Fatalf("failed to decode JSON data: %v", err)
	}

	if readData["key"] != "value" {
		t.Errorf("expected 'key' to be 'value', got %s", readData["key"])
	}
}

func Test_ensureDirExists(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test_ensure_dir_exists")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Fatalf("failed to remove temp directory: %v", err)
		}
	}()

	newDir := filepath.Join(tempDir, "newdir")

	if _, err := os.Stat(newDir); !os.IsNotExist(err) {
		t.Fatalf("expected directory %s to not exist", newDir)
	}

	err = ensureDirExists(newDir)
	if err != nil {
		t.Fatalf("ensureDirExists returned an error: %v", err)
	}

	if _, err := os.Stat(newDir); os.IsNotExist(err) {
		t.Fatalf("expected directory %s to be created", newDir)
	}

	err = ensureDirExists(newDir)
	if err != nil {
		t.Fatalf("ensureDirExists returned an error when directory already exists: %v", err)
	}
}

func Test_ensureFileExists(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test_ensure_file_exists")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Fatalf("failed to remove temp directory: %v", err)
		}
	}()

	newFilePath := filepath.Join(tempDir, "newdir", "testfile.txt")

	err = ensureFileExists(newFilePath)
	if err != nil {
		t.Fatalf("ensureFileExists returned an error: %v", err)
	}

	if _, err := os.Stat(newFilePath); os.IsNotExist(err) {
		t.Fatalf("expected file %s to be created", newFilePath)
	}

	err = ensureFileExists(newFilePath)
	if err != nil {
		t.Fatalf("ensureFileExists returned an error when file already exists: %v", err)
	}
}

func Test_createSymlink(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test_create_symlink")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Fatalf("failed to remove temp directory: %v", err)
		}
	}()

	targetFile := filepath.Join(tempDir, "target.txt")
	linkFile := filepath.Join(tempDir, "link.txt")

	err = os.WriteFile(targetFile, []byte("test data"), 0600)
	if err != nil {
		t.Fatalf("failed to create target file: %v", err)
	}

	err = createSymlink(targetFile, linkFile)
	if err != nil {
		t.Fatalf("createSymlink returned an error: %v", err)
	}

	linkInfo, err := os.Lstat(linkFile)
	if err != nil {
		t.Fatalf("failed to stat symlink: %v", err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Errorf("expected %s to be a symlink", linkFile)
	}

	target, err := os.Readlink(linkFile)
	if err != nil {
		t.Fatalf("failed to read symlink: %v", err)
	}
	if target != targetFile {
		t.Errorf("expected symlink to point to %s, got %s", targetFile, target)
	}

	newTargetFile := filepath.Join(tempDir, "new_target.txt")
	err = os.WriteFile(newTargetFile, []byte("new data"), 0600)
	if err != nil {
		t.Fatalf("failed to create new target file: %v", err)
	}

	err = createSymlink(newTargetFile, linkFile)
	if err != nil {
		t.Fatalf("createSymlink returned an error when replacing symlink: %v", err)
	}

	newTarget, err := os.Readlink(linkFile)
	if err != nil {
		t.Fatalf("failed to read new symlink: %v", err)
	}

	if newTarget != newTargetFile {
		t.Errorf("expected symlink to point to %s, got %s", newTargetFile, newTarget)
	}
}
