// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 Red Hat.
package secureagent

import "testing"

func TestAgent_RunCommandStatus(t *testing.T) {
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
				DhcpLeaseFile:                 DHCLIENT_LEASE_FILE,
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
			if err := a.RunCommandStatus(); (err != nil) != tt.wantErr {
				t.Errorf("RunCommandStatus() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
