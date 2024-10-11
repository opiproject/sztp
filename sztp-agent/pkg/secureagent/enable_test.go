// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 Red Hat.

// Package secureagent implements the secure agent
package secureagent

import "testing"

func TestAgent_RunCommandEnable(t *testing.T) {
	type fields struct {
		BootstrapURL                  []string
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
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "TestAgent_RunCommandEnable",
			fields: fields{
				BootstrapURL:                  []string{"https://localhost:8443"},
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
			}
			if err := a.RunCommandEnable(); (err != nil) != tt.wantErr {
				t.Errorf("RunCommandEnable() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
