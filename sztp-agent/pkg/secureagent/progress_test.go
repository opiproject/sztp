// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 Red Hat.

// Package secureagent implements the secure agent
package secureagent

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProgressTypeString(t *testing.T) {
	tests := []struct {
		input    ProgressType
		expected string
	}{
		{ProgressTypeBootstrapInitiated, "bootstrap-initiated"},
		{ProgressTypeParsingInitiated, "parsing-initiated"},
		{ProgressTypeParsingWarning, "parsing-warning"},
		{ProgressTypeParsingError, "parsing-error"},
		{ProgressTypeParsingComplete, "parsing-complete"},
		{ProgressTypeBootImageInitiated, "boot-image-initiated"},
		{ProgressTypeBootImageWarning, "boot-image-warning"},
		{ProgressTypeBootImageError, "boot-image-error"},
		{ProgressTypeBootImageMismatch, "boot-image-mismatch"},
		{ProgressTypeBootImageInstalledRebooting, "boot-image-installed-rebooting"},
		{ProgressTypeBootImageComplete, "boot-image-complete"},
		{ProgressTypePreScriptInitiated, "pre-script-initiated"},
		{ProgressTypePreScriptWarning, "pre-script-warning"},
		{ProgressTypePreScriptError, "pre-script-error"},
		{ProgressTypePreScriptComplete, "pre-script-complete"},
		{ProgressTypeConfigInitiated, "config-initiated"},
		{ProgressTypeConfigWarning, "config-warning"},
		{ProgressTypeConfigError, "config-error"},
		{ProgressTypeConfigComplete, "config-complete"},
		{ProgressTypePostScriptInitiated, "post-script-initiated"},
		{ProgressTypePostScriptWarning, "post-script-warning"},
		{ProgressTypePostScriptError, "post-script-error"},
		{ProgressTypePostScriptComplete, "post-script-complete"},
		{ProgressTypeBootstrapWarning, "bootstrap-warning"},
		{ProgressTypeBootstrapError, "bootstrap-error"},
		{ProgressTypeBootstrapComplete, "bootstrap-complete"},
		{ProgressTypeInformational, "informational"},
		{ProgressType(999), "unknown"}, // Test for an unknown value
	}

	for _, test := range tests {
		result := test.input.String()
		if result != test.expected {
			t.Errorf("For %v expected %v, but got %v", test.input, test.expected, result)
		}
	}
}

//nolint:funlen
func TestAgent_doReportProgress(t *testing.T) {
	var output []byte
	expected := BootstrapServerPostOutput{
		IetfSztpBootstrapServerOutput: struct {
			ConveyedInformation string `json:"conveyed-information"`
		}{
			ConveyedInformation: "MIIDfwYLKoZIhvcNAQkQASugggNuBIIDansKICAiaWV0Zi1zenRwLWNvbnZleWVkLWluZm86b25ib2FyZGluZy1pbmZvcm1hdGlvbiI6IHsKICAgICJib290LWltYWdlIjogewogICAgICAiZG93bmxvYWQtdXJpIjogWwogICAgICAgICJodHRwOi8vd2ViOjgwODIvdmFyL2xpYi9taXNjL215LWJvb3QtaW1hZ2UuaW1nIiwKICAgICAgICAiZnRwOi8vd2ViOjMwODIvdmFyL2xpYi9taXNjL215LWJvb3QtaW1hZ2UuaW1nIgogICAgICBdLAogICAgICAiaW1hZ2UtdmVyaWZpY2F0aW9uIjogWwogICAgICAgIHsKICAgICAgICAgICJoYXNoLWFsZ29yaXRobSI6ICJpZXRmLXN6dHAtY29udmV5ZWQtaW5mbzpzaGEtMjU2IiwKICAgICAgICAgICJoYXNoLXZhbHVlIjogIjdiOmNhOmU2OmFjOjIzOjA2OmQ4Ojc5OjA2OjhjOmFjOjAzOjgwOmUyOjE2OjQ0OjdlOjQwOjZhOjY1OmZhOmQ0OjY5OjYxOjZlOjA1OmNlOmY1Ojg3OmRjOjJiOjk3IgogICAgICAgIH0KICAgICAgXQogICAgfSwKICAgICJwcmUtY29uZmlndXJhdGlvbi1zY3JpcHQiOiAiSXlFdlltbHVMMkpoYzJnS1pXTm9ieUFpYVc1emFXUmxJSFJvWlNCd2NtVXRZMjl1Wm1sbmRYSmhkR2x2YmkxelkzSnBjSFF1TGk0aUNnPT0iLAogICAgImNvbmZpZ3VyYXRpb24taGFuZGxpbmciOiAibWVyZ2UiLAogICAgImNvbmZpZ3VyYXRpb24iOiAiUEhSdmNDQjRiV3h1Y3owaWFIUjBjSE02TDJWNFlXMXdiR1V1WTI5dEwyTnZibVpwWnlJK0NpQWdQR0Z1ZVMxNGJXd3RZMjl1ZEdWdWRDMXZhMkY1THo0S1BDOTBiM0ErQ2c9PSIsCiAgICAicG9zdC1jb25maWd1cmF0aW9uLXNjcmlwdCI6ICJJeUV2WW1sdUwySmhjMmdLWldOb2J5QWlhVzV6YVdSbElIUm9aU0J3YjNOMExXTnZibVpwWjNWeVlYUnBiMjR0YzJOeWFYQjBMaTR1SWdvPSIKICB9Cn0=",
		},
	}
	expectedFailedBase64 := BootstrapServerPostOutput{
		IetfSztpBootstrapServerOutput: struct {
			ConveyedInformation string `json:"conveyed-information"`
		}{
			ConveyedInformation: "{wrongBASE64}",
		},
	}
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		log.Println(user, pass)

		switch {
		case (user + ":" + pass) == "USER:PASS":
			w.WriteHeader(200)
			output, _ = json.Marshal(expected)
		case (user + ":" + pass) == "KOBASE64:KO":
			w.WriteHeader(200)
			output, _ = json.Marshal(expectedFailedBase64)
		default:
			w.WriteHeader(400)
			output, _ = json.Marshal(expected)
		}

		_, err := fmt.Fprint(w, string(output))
		if err != nil {
			return
		}
	}))
	defer svr.Close()
	type fields struct {
		BootstrapURL             []string
		SerialNumber             string
		DevicePassword           string
		DevicePrivateKey         string
		DeviceEndEntityCert      string
		BootstrapTrustAnchorCert string
		ContentTypeReq           string
		InputJSONContent         string
		DhcpLeaseFile            string
		ProgressJSON             ProgressJSON
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "OK",
			fields: fields{
				BootstrapURL:             []string{svr.URL},
				SerialNumber:             "USER",
				DevicePassword:           "PASS",
				DevicePrivateKey:         "PRIVATEKEY",
				DeviceEndEntityCert:      "ENDENTITYCERT",
				BootstrapTrustAnchorCert: "TRUSTANCHORCERT",
				ContentTypeReq:           "application/vnd.ietf.sztp.bootstrap-server+json",
				InputJSONContent:         "INPUTJSON",
				DhcpLeaseFile:            "DHCPLEASEFILE",
				ProgressJSON:             ProgressJSON{},
			},
			wantErr: false,
		},
		{
			name: "KO",
			fields: fields{
				BootstrapURL:             []string{svr.URL},
				SerialNumber:             "USER",
				DevicePassword:           "PASSWORDWRONG",
				DevicePrivateKey:         "PRIVATEKEY",
				DeviceEndEntityCert:      "ENDENTITYCERT",
				BootstrapTrustAnchorCert: "TRUSTANCHORCERT",
				ContentTypeReq:           "application/vnd.ietf.sztp.bootstrap-server+json",
				InputJSONContent:         "INPUTJSON",
				DhcpLeaseFile:            "DHCPLEASEFILE",
				ProgressJSON:             ProgressJSON{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Agent{
				BootstrapURL:             tt.fields.BootstrapURL,
				SerialNumber:             tt.fields.SerialNumber,
				DevicePassword:           tt.fields.DevicePassword,
				DevicePrivateKey:         tt.fields.DevicePrivateKey,
				DeviceEndEntityCert:      tt.fields.DeviceEndEntityCert,
				BootstrapTrustAnchorCert: tt.fields.BootstrapTrustAnchorCert,
				ContentTypeReq:           tt.fields.ContentTypeReq,
				InputJSONContent:         tt.fields.InputJSONContent,
				DhcpLeaseFile:            tt.fields.DhcpLeaseFile,
				ProgressJSON:             tt.fields.ProgressJSON,
				HttpClient:               &http.Client{},
			}
			if err := a.doReportProgress(ProgressTypeBootstrapInitiated, "Bootstrap Initiated", &tt.fields.BootstrapURL[0]); (err != nil) != tt.wantErr {
				t.Errorf("doReportProgress() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
