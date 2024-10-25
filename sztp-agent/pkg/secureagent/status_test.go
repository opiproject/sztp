// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 Red Hat.

// Package secureagent implements the secure agent
package secureagent

import (
	"testing"
)

const StatusTestContent = `{
  "init": {"errors": [], "start": 1729891263, "end": 0},
  "downloading-file": {"errors": [], "start": 0, "end": 0},
  "pending-reboot": {"errors": [], "start": 0, "end": 0},
  "parsing": {"errors": [], "start": 0, "end": 0},
  "onboarding": {"errors": [], "start": 0, "end": 0},
  "redirect": {"errors": [], "start": 0, "end": 0},
  "boot-image": {"errors": [], "start": 1729891263, "end": 1729891263},
  "pre-script": {"errors": [], "start": 1729891264, "end": 1729891264},
  "config": {"errors": [], "start": 1729891264, "end": 1729891264},
  "post-script": {"errors": [], "start": 1729891264, "end": 1729891264},
  "bootstrap": {"errors": [], "start": 1729891263, "end": 1729891264},
  "is-completed": {"errors": [], "start": 1729891263, "end": 1729891264},
  "informational": "",
  "stage": "is-completed-completed"
}`

const ResultTestContent = `{
  "errors": ["error1", "error2"],
}`

func TestAgent_RunCommandStatus(t *testing.T) {
	testStatusFile := "/tmp/sztp/status.json"
	testResultFile := "/tmp/sztp/result.json"
	testSymLinkDir := "/tmp/symlink"

	type fields struct {
		BootstrapURL                  string
		SerialNumber                  string
		DevicePassword                string
		DevicePrivateKey              string
		DeviceEndEntityCert           string
		BootstrapTrustAnchorCert      string
		ContentTypeReq                string
		InputJSONContent              string
		DhcpLeaseFile                 string
		ProgressJSON                  ProgressJSON
		BootstrapServerOnboardingInfo BootstrapServerOnboardingInfo
		BootstrapServerRedirectInfo   BootstrapServerRedirectInfo
		StatusFilePath                string
		ResultFilePath                string
		SymLinkDir                    string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "TestAgent_RunCommandStatus",
			fields: fields{
				BootstrapURL:                  "https://localhost:8443",
				SerialNumber:                  "1234567890",
				DevicePassword:                "password",
				DevicePrivateKey:              "privateKey",
				DeviceEndEntityCert:           "endEntityCert",
				BootstrapTrustAnchorCert:      "trustAnchorCert",
				ContentTypeReq:                "application/json",
				InputJSONContent:              generateInputJSONContent(),
				DhcpLeaseFile:                 "DHCPLEASEFILE",
				ProgressJSON:                  ProgressJSON{},
				BootstrapServerRedirectInfo:   BootstrapServerRedirectInfo{},
				BootstrapServerOnboardingInfo: BootstrapServerOnboardingInfo{},
				StatusFilePath:                testStatusFile,
				ResultFilePath:                testResultFile,
				SymLinkDir:                    testSymLinkDir,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Agent{
				BootstrapURL:                  tt.fields.BootstrapURL,
				SerialNumber:                  tt.fields.SerialNumber,
				DevicePassword:                tt.fields.DevicePassword,
				DevicePrivateKey:              tt.fields.DevicePrivateKey,
				DeviceEndEntityCert:           tt.fields.DeviceEndEntityCert,
				BootstrapTrustAnchorCert:      tt.fields.BootstrapTrustAnchorCert,
				ContentTypeReq:                tt.fields.ContentTypeReq,
				InputJSONContent:              tt.fields.InputJSONContent,
				DhcpLeaseFile:                 tt.fields.DhcpLeaseFile,
				ProgressJSON:                  tt.fields.ProgressJSON,
				BootstrapServerOnboardingInfo: tt.fields.BootstrapServerOnboardingInfo,
				BootstrapServerRedirectInfo:   tt.fields.BootstrapServerRedirectInfo,
				StatusFilePath:                tt.fields.StatusFilePath,
				ResultFilePath:                tt.fields.ResultFilePath,
				SymLinkDir:                    tt.fields.SymLinkDir,
			}
			if err := a.prepareStatus(); err != nil {
				t.Errorf("prepareStatus() error = %v", err)
			}
			if err := a.RunCommandStatus(); (err != nil) != tt.wantErr {
				t.Errorf("RunCommandStatus() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
