/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

package secureagent

import (
	"encoding/base64"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

func readSSHHostKeyPublicFiles(pattern string) []ssh.PublicKey {
	results := []ssh.PublicKey{}

	files, err := filepath.Glob(pattern)
	if err != nil {
		log.Printf("[ERROR] Error getting ssh host public keys file list: %v", err)
		return results
	}

	for _, f := range files {
		// nolint:gosec
		data, err := os.ReadFile(f)
		if err != nil {
			log.Printf("[ERROR] Error reading public key file %s: %v", f, err)
			continue
		}

		key, _, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			log.Printf("[ERROR] Problem parsing public key file %s: %v\n"+
				"Check the key file has the correct format", f, err.Error())
			continue
		}
		results = append(results, key)
	}
	return results
}

func getSSHHostKeyString(key ssh.PublicKey, fullString bool) string {
	if fullString {
		return strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(key)), "\n") // returns algorithm + key
	}
	return base64.StdEncoding.EncodeToString(key.Marshal()) // returns just the key
}
