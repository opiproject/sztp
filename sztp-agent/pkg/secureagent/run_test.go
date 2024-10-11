// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 Red Hat.

// Package secureagent implements the secure agent
package secureagent

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
)

const DHCPTestContent1 = `lease {
  interface "eth0";
  fixed-address 10.127.127.100;
  filename "grubx64.efi";
  option subnet-mask 255.255.255.0;
  option sztp-redirect-urls "http://
  option dhcp-lease-time 600;
  option tftp-server-name "w.x.y.z";
  option bootfile-name "test.cfg";
  option dhcp-message-type 5;
  option dhcp-server-identifier 10.127.127.2;
  renew 1 2022/08/15 19:16:40;
  rebind 1 2022/08/15 19:20:50;
  expire 1 2022/08/15 19:22:05;
}`

func TestAgent_RunCommand(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	
	type fields struct {
		InputBootstrapURL             string
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

	expectedOnboarding := BootstrapServerPostOutput{
		IetfSztpBootstrapServerOutput: struct {
			ConveyedInformation string `json:"conveyed-information"`
		}{
			ConveyedInformation: "MIIDYwYLKoZIhvcNAQkQASugggNSBIIDTnsKICAiaWV0Zi1zenRwLWNvbnZleWVkLWluZm86b25ib2FyZGluZy1pbmZvcm1hdGlvbiI6IHsKICAgICJib290LWltYWdlIjogewogICAgICAiZG93bmxvYWQtdXJpIjogWwogICAgICAgICJodHRwczovL3dlYjo0NDMvdGVzdC5pbWciLAogICAgICAgICJmdHBzOi8vd2ViOjk5MC90ZXN0LmltZyIKICAgICAgXSwKICAgICAgImltYWdlLXZlcmlmaWNhdGlvbiI6IFsKICAgICAgICB7CiAgICAgICAgICAiaGFzaC1hbGdvcml0aG0iOiAiaWV0Zi1zenRwLWNvbnZleWVkLWluZm86c2hhLTI1NiIsCiAgICAgICAgICAiaGFzaC12YWx1ZSI6ICJlMzpiMDpjNDo0Mjo5ODpmYzoxYzoxNDo5YTpmYjpmNDpjODo5OTo2ZjpiOToyNDoyNzphZTo0MTplNDo2NDo5Yjo5Mzo0YzphNDo5NTo5OToxYjo3ODo1MjpiODo1NSIKICAgICAgICB9CiAgICAgIF0KICAgIH0sCiAgICAicHJlLWNvbmZpZ3VyYXRpb24tc2NyaXB0IjogIkl5RXZZbWx1TDJKaGMyZ0taV05vYnlBaWFXNXphV1JsSUhSb1pTQjBhR2x5WkMxd2NtVXRZMjl1Wm1sbmRYSmhkR2x2YmkxelkzSnBjSFF1TGk0aUNnPT0iLAogICAgImNvbmZpZ3VyYXRpb24taGFuZGxpbmciOiAibWVyZ2UiLAogICAgImNvbmZpZ3VyYXRpb24iOiAiUEhSdmNDQjRiV3h1Y3owaWFIUjBjSE02TDJWNFlXMXdiR1V1WTI5dEwyTnZibVpwWnlJK0NpQWdQR0Z1ZVMxNGJXd3RZMjl1ZEdWdWRDMXZhMkY1THo0S1BDOTBiM0ErQ2c9PSIsCiAgICAicG9zdC1jb25maWd1cmF0aW9uLXNjcmlwdCI6ICJJeUV2WW1sdUwySmhjMmdLWldOb2J5QWlhVzV6YVdSbElIUm9aU0IwYUdseVpDMXdiM04wTFdOdmJtWnBaM1Z5WVhScGIyNHRjMk55YVhCMExpNHVJZ289IgogIH0KfQ==",
		},
	}

	httpmock.RegisterResponder("POST", "https://run-command.com", func(req *http.Request) (*http.Response, error) {
        user, pass, _ := req.BasicAuth()

		if (user + ":" + pass) == "USER:PASS" {
			output, _ := json.Marshal(expectedOnboarding)
			return httpmock.NewStringResponse(200, string(output)), nil
		}
		return httpmock.NewStringResponse(401, ""), nil
	})

	httpmock.RegisterResponder("GET", "https://web:443/test.img", func(req *http.Request) (*http.Response, error) {
		return httpmock.NewBytesResponse(200, []byte{}), nil
	})

	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{

		{
			name: "TestAgent_RunCommand",
			fields: fields{
				InputBootstrapURL:        "https://run-command.com",
				SerialNumber:             "USER",
				DevicePassword:           "PASS",
				DevicePrivateKey:         "/certs/second_private_key.pem",
				DeviceEndEntityCert:      "/certs/second_my_cert.pem",
				BootstrapTrustAnchorCert: "/certs/opi.pem",
				ContentTypeReq:           "application/yang-data+json",
				InputJSONContent:         generateInputJSONContent(),
				DhcpLeaseFile:            "",
				ProgressJSON:             ProgressJSON{},
				BootstrapServerOnboardingInfo: BootstrapServerOnboardingInfo{},
				BootstrapServerRedirectInfo:   BootstrapServerRedirectInfo{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Agent{
				InputBootstrapURL:             tt.fields.InputBootstrapURL,
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
				HttpClient:					   &http.Client{},
			}
			if err := a.RunCommand(); (err != nil) != tt.wantErr {
				t.Errorf("RunCommand() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
