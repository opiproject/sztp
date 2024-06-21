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
	"os"
	"testing"
)

const DHCPTestContent = `lease {
  interface "eth0";
  fixed-address 10.127.127.100;
  filename "grubx64.efi";
  option subnet-mask 255.255.255.0;
  option sztp-redirect-urls "http://mymock/test";
  option dhcp-lease-time 600;
  option tftp-server-name "w.x.y.z";
  option bootfile-name "test.cfg";
  option dhcp-message-type 5;
  option dhcp-server-identifier 10.127.127.2;
  renew 1 2022/08/15 19:16:40;
  rebind 1 2022/08/15 19:20:50;
  expire 1 2022/08/15 19:22:05;
}`

//nolint:funlen
func TestAgent_getBootstrapURL(t *testing.T) {
	dhcpTestFileOK := "/tmp/test.dhcp"
	createTempTestFile(dhcpTestFileOK, DHCPTestContent, true)

	type fields struct {
		BootstrapURL             string
		SerialNumber             string
		DevicePassword           string
		DevicePrivateKey         string
		DeviceEndEntityCert      string
		BootstrapTrustAnchorCert string
		ContentTypeReq           string
		InputJSONContent         string
		DhcpLeasesFile           string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Test OK Case file exists and get url successfully",
			fields: fields{
				BootstrapURL:             "http://localhost",
				SerialNumber:             "my-serial-number",
				DevicePassword:           "my-password",
				DevicePrivateKey:         "",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "",
				ContentTypeReq:           CONTENT_TYPE_YANG,
				InputJSONContent:         "",
				DhcpLeasesFile:           dhcpTestFileOK,
			},
			wantErr: false,
		},
		{
			name: "Test KO when not file found",
			fields: fields{
				BootstrapURL:             "http://localhost",
				SerialNumber:             "my-serial-number",
				DevicePassword:           "my-password",
				DevicePrivateKey:         "",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "",
				ContentTypeReq:           CONTENT_TYPE_YANG,
				InputJSONContent:         "",
				DhcpLeasesFile:           "/kk/kk",
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
				DhcpLeaseFile:            tt.fields.DhcpLeasesFile,
			}
			if err := a.getBootstrapURL(); (err != nil) != tt.wantErr {
				t.Errorf("runDaemon() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	deleteTempTestFile(dhcpTestFileOK)
}

func createTempTestFile(file string, content string, _ bool) {
	log.Println("Creating file " + file)
	// nolint:gosec
	f, err := os.Create(file)
	if err != nil {
		log.Fatal(err)
	}

	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			log.Fatalf("Unable to close file %s: %v", f.Name(), err)
		}
	}(f)

	_, err = f.WriteString(content)
	if err != nil {
		log.Printf("Could not write to file %s: %v", f.Name(), err)
	}
}

func deleteTempTestFile(file string) {
	log.Println("Deleting file " + file)
	err := os.RemoveAll(file)

	if err != nil {
		fmt.Println(err)
		return
	}
}

//nolint:funlen
func TestAgent_doReqBootstrap(t *testing.T) {
	var output []byte
	expectedOnboarding := BootstrapServerPostOutput{
		IetfSztpBootstrapServerOutput: struct {
			ConveyedInformation string `json:"conveyed-information"`
		}{
			ConveyedInformation: "MIIDfwYLKoZIhvcNAQkQASugggNuBIIDansKICAiaWV0Zi1zenRwLWNvbnZleWVkLWluZm86b25ib2FyZGluZy1pbmZvcm1hdGlvbiI6IHsKICAgICJib290LWltYWdlIjogewogICAgICAiZG93bmxvYWQtdXJpIjogWwogICAgICAgICJodHRwOi8vd2ViOjgwODIvdmFyL2xpYi9taXNjL215LWJvb3QtaW1hZ2UuaW1nIiwKICAgICAgICAiZnRwOi8vd2ViOjMwODIvdmFyL2xpYi9taXNjL215LWJvb3QtaW1hZ2UuaW1nIgogICAgICBdLAogICAgICAiaW1hZ2UtdmVyaWZpY2F0aW9uIjogWwogICAgICAgIHsKICAgICAgICAgICJoYXNoLWFsZ29yaXRobSI6ICJpZXRmLXN6dHAtY29udmV5ZWQtaW5mbzpzaGEtMjU2IiwKICAgICAgICAgICJoYXNoLXZhbHVlIjogIjdiOmNhOmU2OmFjOjIzOjA2OmQ4Ojc5OjA2OjhjOmFjOjAzOjgwOmUyOjE2OjQ0OjdlOjQwOjZhOjY1OmZhOmQ0OjY5OjYxOjZlOjA1OmNlOmY1Ojg3OmRjOjJiOjk3IgogICAgICAgIH0KICAgICAgXQogICAgfSwKICAgICJwcmUtY29uZmlndXJhdGlvbi1zY3JpcHQiOiAiSXlFdlltbHVMMkpoYzJnS1pXTm9ieUFpYVc1emFXUmxJSFJvWlNCd2NtVXRZMjl1Wm1sbmRYSmhkR2x2YmkxelkzSnBjSFF1TGk0aUNnPT0iLAogICAgImNvbmZpZ3VyYXRpb24taGFuZGxpbmciOiAibWVyZ2UiLAogICAgImNvbmZpZ3VyYXRpb24iOiAiUEhSdmNDQjRiV3h1Y3owaWFIUjBjSE02TDJWNFlXMXdiR1V1WTI5dEwyTnZibVpwWnlJK0NpQWdQR0Z1ZVMxNGJXd3RZMjl1ZEdWdWRDMXZhMkY1THo0S1BDOTBiM0ErQ2c9PSIsCiAgICAicG9zdC1jb25maWd1cmF0aW9uLXNjcmlwdCI6ICJJeUV2WW1sdUwySmhjMmdLWldOb2J5QWlhVzV6YVdSbElIUm9aU0J3YjNOMExXTnZibVpwWjNWeVlYUnBiMjR0YzJOeWFYQjBMaTR1SWdvPSIKICB9Cn0=",
		},
	}
	expectedRedirect := BootstrapServerPostOutput{
		IetfSztpBootstrapServerOutput: struct {
			ConveyedInformation string `json:"conveyed-information"`
		}{
			ConveyedInformation: "MIIHlgYLKoZIhvcNAQkQASugggeFBIIHgXsKICAiaWV0Zi1zenRwLWNvbnZleWVkLWluZm86cmVkaXJlY3QtaW5mb3JtYXRpb24iOiB7CiAgICAiYm9vdHN0cmFwLXNlcnZlciI6IFsKICAgICAgewogICAgICAgICJhZGRyZXNzIjogIjEyNy4wLjAuMSIsCiAgICAgICAgInBvcnQiOiAzODQ0MywKICAgICAgICAidHJ1c3QtYW5jaG9yIjogIk1JSUZEd1lKS29aSWh2Y05BUWNDb0lJRkFEQ0NCUHdDQVFFeEFEQUxCZ2txaGtpRzl3MEJCd0dnZ2dUa01JSUNXVENDQWYrZ0F3SUJBZ0lCQVRBS0JnZ3Foa2pPUFFRREFqQjFNUXN3Q1FZRFZRUUdFd0pZV0RFZE1Cc0dBMVVFQ0F3VVRYa2dVM1JoZEdVZ2IzSWdVSEp2ZG1sdVkyVXhHREFXQmdOVkJBb01EMDE1SUU5eVoyRnVhWHBoZEdsdmJqRVFNQTRHQTFVRUN3d0hUWGtnVlc1cGRERWJNQmtHQTFVRUF3d1NjMkpwTDNObGNuWmxjaTl5YjI5MExXTmhNQ0FYRFRJeU1UQXhOekV5TVRZeE5Gb1lEems1T1RreE1qTXhNak0xT1RVNVdqQjFNUXN3Q1FZRFZRUUdFd0pZV0RFZE1Cc0dBMVVFQ0F3VVRYa2dVM1JoZEdVZ2IzSWdVSEp2ZG1sdVkyVXhHREFXQmdOVkJBb01EMDE1SUU5eVoyRnVhWHBoZEdsdmJqRVFNQTRHQTFVRUN3d0hUWGtnVlc1cGRERWJNQmtHQTFVRUF3d1NjMkpwTDNObGNuWmxjaTl5YjI5MExXTmhNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVQOFhDSEJzYkQwS3lQWk9DdjI3clI5cDhTd2FDK3R0U1Q1cGpKMmtOUUF2UFVyWXZKT2RGWkJCd20xTmtLU3ducjZQdmFNdGgxdi92VmxRV0U3b0dBNk4rTUh3d0hRWURWUjBPQkJZRUZNNTBPVmp2WW5Ed1NTZ3dNNnB1bEN4aXhJQ1hNQXdHQTFVZEV3UUZNQU1CQWY4d0RnWURWUjBQQVFIL0JBUURBZ0VHTUQwR0ExVWRId1EyTURRd01xQXdvQzZHTEdoMGRIQTZMeTlqY213dVpYaGhiWEJzWlM1amIyMC9ZMkU5YzJKcE9uTmxjblpsY2pweWIyOTBMV05oTUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSUJHRHdFcXBVaFNaQUs0bjh1K1BhUUZyU2VHa2QvQkJaT3F6cXZBYTlkNjBBaUVBcEVYdWRSY0xwRkV5SHBOeldrMlFoV1IycDNrMCtuaHRGMHpROFZ1VTdHY3dnZ0tETUlJQ0tLQURBZ0VDQWdFQ01Bb0dDQ3FHU000OUJBTUNNSFV4Q3pBSkJnTlZCQVlUQWxoWU1SMHdHd1lEVlFRSURCUk5lU0JUZEdGMFpTQnZjaUJRY205MmFXNWpaVEVZTUJZR0ExVUVDZ3dQVFhrZ1QzSm5ZVzVwZW1GMGFXOXVNUkF3RGdZRFZRUUxEQWROZVNCVmJtbDBNUnN3R1FZRFZRUUREQkp6WW1rdmMyVnlkbVZ5TDNKdmIzUXRZMkV3SUJjTk1qSXhNREUzTVRJeE5qRTBXaGdQT1RrNU9URXlNekV5TXpVNU5UbGFNSHN4Q3pBSkJnTlZCQVlUQWxoWU1SMHdHd1lEVlFRSURCUk5lU0JUZEdGMFpTQnZjaUJRY205MmFXNWpaVEVZTUJZR0ExVUVDZ3dQVFhrZ1QzSm5ZVzVwZW1GMGFXOXVNUkF3RGdZRFZRUUxEQWROZVNCVmJtbDBNU0V3SHdZRFZRUUREQmh6WW1rdmMyVnlkbVZ5TDJsdWRHVnliV1ZrYVdGMFpURXdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBU0xYQVBGNFo5Skw4OTQxbllRU3VoWFMrWTJxbjlPdGp5cG9leXJPVkl4ZDc1dngyN1dYRWtWcmk3Q2NnQURlenFpK2RvZjRLd2pzRWljdDJCNlp0aDdvNEdnTUlHZE1CMEdBMVVkRGdRV0JCUUQ3L1FEazhrL2hiWHltY28zRElBdWV0dnV4ekFmQmdOVkhTTUVHREFXZ0JUT2REbFk3Mkp3OEVrb01ET3FicFFzWXNTQWx6QU1CZ05WSFJNRUJUQURBUUgvTUE0R0ExVWREd0VCL3dRRUF3SUJCakE5QmdOVkhSOEVOakEwTURLZ01LQXVoaXhvZEhSd09pOHZZM0pzTG1WNFlXMXdiR1V1WTI5dFAyTmhQWE5pYVRwelpYSjJaWEk2Y205dmRDMWpZVEFLQmdncWhrak9QUVFEQWdOSkFEQkdBaUVBa0lKOG9HMjhsWmhWejNGWGRsNFgwWExwZlY3T3k5ZFdlTGVHMUhtRmwzTUNJUUNURFZRQ3lQTXNhOXNLdFBzcGNOQXlYazBOUVIrRVdpQjBzcldrVzYyd0J6RUEiCiAgICAgIH0KICAgIF0KICB9Cn0=",
		},
	}
	expectedFailedBase64 := BootstrapServerPostOutput{
		IetfSztpBootstrapServerOutput: struct {
			ConveyedInformation string `json:"conveyed-information"`
		}{
			ConveyedInformation: "{wrongBASE64}",
		},
	}
	expectedError := BootstrapServerErrorOutput{
		IetfRestconfErrors: struct {
			Error []struct {
				ErrorType    string `json:"error-type"`
				ErrorTag     string `json:"error-tag"`
				ErrorMessage string `json:"error-message"`
			} `json:"error"`
		}{
			Error: []struct {
				ErrorType    string `json:"error-type"`
				ErrorTag     string `json:"error-tag"`
				ErrorMessage string `json:"error-message"`
			}{
				{
					ErrorType:    "protocol",
					ErrorTag:     "access-denied",
					ErrorMessage: "failed",
				},
			},
		},
	}
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		log.Println(user, pass)

		switch {
		case (user + ":" + pass) == "USER:PASS":
			w.WriteHeader(200)
			output, _ = json.Marshal(expectedOnboarding)
		case (user + ":" + pass) == "REDIRECT:PASS":
			w.WriteHeader(200)
			output, _ = json.Marshal(expectedRedirect)
		case (user + ":" + pass) == "KOBASE64:KO":
			w.WriteHeader(200)
			output, _ = json.Marshal(expectedFailedBase64)
		case (user + ":" + pass) == "KO:KO":
			w.WriteHeader(401)
			output, _ = json.Marshal(expectedError)
		default:
			w.WriteHeader(400)
			output, _ = json.Marshal(expectedOnboarding)
		}
		_, err := fmt.Fprint(w, string(output))
		if err != nil {
			return
		}
	}))
	defer svr.Close()

	type fields struct {
		BootstrapURL             string
		SerialNumber             string
		DevicePassword           string
		DevicePrivateKey         string
		DeviceEndEntityCert      string
		BootstrapTrustAnchorCert string
		ContentTypeReq           string
		InputJSONContent         string
		DhcpLeaseFile            string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Test OK passing all the Onboarding information",
			fields: fields{
				BootstrapURL:             svr.URL,
				SerialNumber:             "USER",
				DevicePassword:           "PASS",
				DevicePrivateKey:         "",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "",
				ContentTypeReq:           "",
				InputJSONContent:         "",
				DhcpLeaseFile:            "",
			},
			wantErr: false,
		},
		{
			name: "Test OK passing all the Redirect information",
			fields: fields{
				BootstrapURL:             svr.URL,
				SerialNumber:             "REDIRECT",
				DevicePassword:           "PASS",
				DevicePrivateKey:         "",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "",
				ContentTypeReq:           "",
				InputJSONContent:         "",
				DhcpLeaseFile:            "",
			},
			wantErr: false,
		},
		{
			name: "Test KO getting error with basic auth",
			fields: fields{
				BootstrapURL:             svr.URL,
				SerialNumber:             "KO",
				DevicePassword:           "KO",
				DevicePrivateKey:         "",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "",
				ContentTypeReq:           "",
				InputJSONContent:         "",
				DhcpLeaseFile:            "",
			},
			wantErr: true,
		},
		{
			name: "Test KO getting error with wrong Base64 output",
			fields: fields{
				BootstrapURL:             svr.URL,
				SerialNumber:             "KOBASE64",
				DevicePassword:           "KO",
				DevicePrivateKey:         "",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "",
				ContentTypeReq:           "",
				InputJSONContent:         "",
				DhcpLeaseFile:            "",
			},
			wantErr: true,
		},
		{
			name: "Test KO pointint to wrong url",
			fields: fields{
				BootstrapURL:             "http://wrongURL",
				SerialNumber:             "KOBASE64",
				DevicePassword:           "KO",
				DevicePrivateKey:         "",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "",
				ContentTypeReq:           "",
				InputJSONContent:         "",
				DhcpLeaseFile:            "",
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
			}
			if err := a.doRequestBootstrapServerOnboardingInfo(); (err != nil) != tt.wantErr {
				t.Errorf("doRequestBootstrapServer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
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
		BootstrapURL             string
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
				BootstrapURL:             svr.URL,
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
				BootstrapURL:             svr.URL,
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
			}
			if err := a.doReportProgress(ProgressTypeBootstrapInitiated); (err != nil) != tt.wantErr {
				t.Errorf("doReportProgress() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

//nolint:funlen
func TestAgent_downloadAndValidateImage(t *testing.T) {
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/imageOK" {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(400)
		}
	}))
	defer svr.Close()

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
			name: "error writing file",
			fields: fields{
				BootstrapURL:             "",
				SerialNumber:             "",
				DevicePassword:           "",
				DevicePrivateKey:         "",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "",
				ContentTypeReq:           "",
				InputJSONContent:         "",
				DhcpLeaseFile:            "",
				ProgressJSON:             ProgressJSON{},
				BootstrapServerOnboardingInfo: BootstrapServerOnboardingInfo{
					IetfSztpConveyedInfoOnboardingInformation: struct {
						InfoTimestampReference string
						BootImage              struct {
							DownloadURI       []string `json:"download-uri"`
							ImageVerification []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							} `json:"image-verification"`
						} `json:"boot-image"`
						PreConfigurationScript  string `json:"pre-configuration-script"`
						ConfigurationHandling   string `json:"configuration-handling"`
						Configuration           string `json:"configuration"`
						PostConfigurationScript string `json:"post-configuration-script"`
					}{
						InfoTimestampReference: "",
						BootImage: struct {
							DownloadURI       []string `json:"download-uri"`
							ImageVerification []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							} `json:"image-verification"`
						}{
							DownloadURI:       []string{"WrongURL"},
							ImageVerification: nil,
						},
						PreConfigurationScript:  "",
						ConfigurationHandling:   "",
						Configuration:           "",
						PostConfigurationScript: "",
					},
				},
				BootstrapServerRedirectInfo: BootstrapServerRedirectInfo{},
			},
			wantErr: true,
		},
		{
			name: "Image wrong",
			fields: fields{
				BootstrapURL:             "",
				SerialNumber:             "",
				DevicePassword:           "",
				DevicePrivateKey:         "",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "",
				ContentTypeReq:           "",
				InputJSONContent:         "",
				DhcpLeaseFile:            "",
				ProgressJSON:             ProgressJSON{},
				BootstrapServerOnboardingInfo: BootstrapServerOnboardingInfo{
					IetfSztpConveyedInfoOnboardingInformation: struct {
						InfoTimestampReference string
						BootImage              struct {
							DownloadURI       []string `json:"download-uri"`
							ImageVerification []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							} `json:"image-verification"`
						} `json:"boot-image"`
						PreConfigurationScript  string `json:"pre-configuration-script"`
						ConfigurationHandling   string `json:"configuration-handling"`
						Configuration           string `json:"configuration"`
						PostConfigurationScript string `json:"post-configuration-script"`
					}{
						InfoTimestampReference: "TIMESTAMP",
						BootImage: struct {
							DownloadURI       []string `json:"download-uri"`
							ImageVerification []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							} `json:"image-verification"`
						}{
							DownloadURI:       []string{svr.URL + "/imageWRONG"},
							ImageVerification: nil,
						},
						PreConfigurationScript:  "",
						ConfigurationHandling:   "",
						Configuration:           "",
						PostConfigurationScript: "",
					},
				},
				BootstrapServerRedirectInfo: BootstrapServerRedirectInfo{},
			},
			wantErr: true,
		},
		{
			name: "Image wrong",
			fields: fields{
				BootstrapURL:             "",
				SerialNumber:             "",
				DevicePassword:           "",
				DevicePrivateKey:         "",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "",
				ContentTypeReq:           "",
				InputJSONContent:         "",
				DhcpLeaseFile:            "",
				ProgressJSON:             ProgressJSON{},
				BootstrapServerOnboardingInfo: BootstrapServerOnboardingInfo{
					IetfSztpConveyedInfoOnboardingInformation: struct {
						InfoTimestampReference string
						BootImage              struct {
							DownloadURI       []string `json:"download-uri"`
							ImageVerification []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							} `json:"image-verification"`
						} `json:"boot-image"`
						PreConfigurationScript  string `json:"pre-configuration-script"`
						ConfigurationHandling   string `json:"configuration-handling"`
						Configuration           string `json:"configuration"`
						PostConfigurationScript string `json:"post-configuration-script"`
					}{
						InfoTimestampReference: "TIMESTAMP",
						BootImage: struct {
							DownloadURI       []string `json:"download-uri"`
							ImageVerification []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							} `json:"image-verification"`
						}{
							DownloadURI:       []string{},
							ImageVerification: nil,
						},
						PreConfigurationScript:  "",
						ConfigurationHandling:   "",
						Configuration:           "",
						PostConfigurationScript: "",
					},
				},
				BootstrapServerRedirectInfo: BootstrapServerRedirectInfo{},
			},
			wantErr: false,
		},
		{
			name: "OK Case but with error due to hash checksum",
			fields: fields{
				BootstrapURL:             "",
				SerialNumber:             "",
				DevicePassword:           "",
				DevicePrivateKey:         "",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "",
				ContentTypeReq:           "",
				InputJSONContent:         "",
				DhcpLeaseFile:            "",
				ProgressJSON:             ProgressJSON{},
				BootstrapServerOnboardingInfo: BootstrapServerOnboardingInfo{
					IetfSztpConveyedInfoOnboardingInformation: struct {
						InfoTimestampReference string
						BootImage              struct {
							DownloadURI       []string `json:"download-uri"`
							ImageVerification []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							} `json:"image-verification"`
						} `json:"boot-image"`
						PreConfigurationScript  string `json:"pre-configuration-script"`
						ConfigurationHandling   string `json:"configuration-handling"`
						Configuration           string `json:"configuration"`
						PostConfigurationScript string `json:"post-configuration-script"`
					}{
						InfoTimestampReference: "TIMESTAMP",
						BootImage: struct {
							DownloadURI       []string `json:"download-uri"`
							ImageVerification []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							} `json:"image-verification"`
						}{
							DownloadURI: []string{svr.URL + "/imageOK"},
							ImageVerification: []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							}{{
								HashAlgorithm: "ietf-sztp-conveyed-info:sha-256",
								HashValue:     "d41d8cd98f00b204e9800998ecf8427e",
							}},
						},
						PreConfigurationScript:  "",
						ConfigurationHandling:   "",
						Configuration:           "",
						PostConfigurationScript: "",
					},
				},
				BootstrapServerRedirectInfo: BootstrapServerRedirectInfo{},
			},
			wantErr: true,
		},
		{
			name: "OK Case but with error due to hash checksum",
			fields: fields{
				BootstrapURL:             "",
				SerialNumber:             "",
				DevicePassword:           "",
				DevicePrivateKey:         "",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "",
				ContentTypeReq:           "",
				InputJSONContent:         "",
				DhcpLeaseFile:            "",
				ProgressJSON:             ProgressJSON{},
				BootstrapServerOnboardingInfo: BootstrapServerOnboardingInfo{
					IetfSztpConveyedInfoOnboardingInformation: struct {
						InfoTimestampReference string
						BootImage              struct {
							DownloadURI       []string `json:"download-uri"`
							ImageVerification []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							} `json:"image-verification"`
						} `json:"boot-image"`
						PreConfigurationScript  string `json:"pre-configuration-script"`
						ConfigurationHandling   string `json:"configuration-handling"`
						Configuration           string `json:"configuration"`
						PostConfigurationScript string `json:"post-configuration-script"`
					}{
						InfoTimestampReference: "TIMESTAMP",
						BootImage: struct {
							DownloadURI       []string `json:"download-uri"`
							ImageVerification []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							} `json:"image-verification"`
						}{
							DownloadURI: []string{svr.URL + "/imageOK"},
							ImageVerification: []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							}{{
								HashAlgorithm: "WRONG HASH ALGORITHM",
								HashValue:     "d41d8cd98f00b204e9800998ecf8427e",
							}},
						},
						PreConfigurationScript:  "",
						ConfigurationHandling:   "",
						Configuration:           "",
						PostConfigurationScript: "",
					},
				},
				BootstrapServerRedirectInfo: BootstrapServerRedirectInfo{},
			},
			wantErr: true,
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
			if err := a.downloadAndValidateImage(); (err != nil) != tt.wantErr {
				t.Errorf("downloadAndValidateImage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// nolint:funlen
func TestAgent_copyConfigurationFile(t *testing.T) {
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
			name: "Error Writing file",
			fields: fields{
				BootstrapURL:             "",
				SerialNumber:             "",
				DevicePassword:           "",
				DevicePrivateKey:         "",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "",
				ContentTypeReq:           "",
				InputJSONContent:         "",
				DhcpLeaseFile:            "",
				ProgressJSON:             ProgressJSON{},
				BootstrapServerOnboardingInfo: BootstrapServerOnboardingInfo{
					IetfSztpConveyedInfoOnboardingInformation: struct {
						InfoTimestampReference string
						BootImage              struct {
							DownloadURI       []string `json:"download-uri"`
							ImageVerification []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							} `json:"image-verification"`
						} `json:"boot-image"`
						PreConfigurationScript  string `json:"pre-configuration-script"`
						ConfigurationHandling   string `json:"configuration-handling"`
						Configuration           string `json:"configuration"`
						PostConfigurationScript string `json:"post-configuration-script"`
					}{
						InfoTimestampReference: " ../ ",
						BootImage: struct {
							DownloadURI       []string `json:"download-uri"`
							ImageVerification []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							} `json:"image-verification"`
						}{
							DownloadURI: []string{},
							ImageVerification: []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							}{{
								HashAlgorithm: "md5",
								HashValue:     "d41d8cd98f00b204e9800998ecf8427e",
							}},
						},
						PreConfigurationScript:  "",
						ConfigurationHandling:   "",
						Configuration:           "",
						PostConfigurationScript: "",
					},
				},
				BootstrapServerRedirectInfo: BootstrapServerRedirectInfo{},
			},
			wantErr: true,
		},
		{
			name: "OK Case",
			fields: fields{
				BootstrapURL:             "",
				SerialNumber:             "",
				DevicePassword:           "",
				DevicePrivateKey:         "",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "",
				ContentTypeReq:           "",
				InputJSONContent:         "",
				DhcpLeaseFile:            "",
				ProgressJSON:             ProgressJSON{},
				BootstrapServerOnboardingInfo: BootstrapServerOnboardingInfo{
					IetfSztpConveyedInfoOnboardingInformation: struct {
						InfoTimestampReference string
						BootImage              struct {
							DownloadURI       []string `json:"download-uri"`
							ImageVerification []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							} `json:"image-verification"`
						} `json:"boot-image"`
						PreConfigurationScript  string `json:"pre-configuration-script"`
						ConfigurationHandling   string `json:"configuration-handling"`
						Configuration           string `json:"configuration"`
						PostConfigurationScript string `json:"post-configuration-script"`
					}{
						InfoTimestampReference: "PATHOK",
						BootImage: struct {
							DownloadURI       []string `json:"download-uri"`
							ImageVerification []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							} `json:"image-verification"`
						}{
							DownloadURI: []string{},
							ImageVerification: []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							}{{
								HashAlgorithm: "md5",
								HashValue:     "d41d8cd98f00b204e9800998ecf8427e",
							}},
						},
						PreConfigurationScript:  "",
						ConfigurationHandling:   "",
						Configuration:           "",
						PostConfigurationScript: "",
					},
				},
				BootstrapServerRedirectInfo: BootstrapServerRedirectInfo{},
			},
			wantErr: false,
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
			if err := a.copyConfigurationFile(); (err != nil) != tt.wantErr {
				t.Errorf("copyConfigurationFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// nolint:funlen
func TestAgent_launchScriptsConfiguration(t *testing.T) {
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
	type args struct {
		typeOf string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			args: args{typeOf: "default or pre"},
			name: "OK Case with PRE",
			fields: fields{
				BootstrapURL:             "",
				SerialNumber:             "",
				DevicePassword:           "",
				DevicePrivateKey:         "",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "",
				ContentTypeReq:           "",
				InputJSONContent:         "",
				DhcpLeaseFile:            "",
				ProgressJSON:             ProgressJSON{},
				BootstrapServerOnboardingInfo: BootstrapServerOnboardingInfo{
					IetfSztpConveyedInfoOnboardingInformation: struct {
						InfoTimestampReference string
						BootImage              struct {
							DownloadURI       []string `json:"download-uri"`
							ImageVerification []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							} `json:"image-verification"`
						} `json:"boot-image"`
						PreConfigurationScript  string `json:"pre-configuration-script"`
						ConfigurationHandling   string `json:"configuration-handling"`
						Configuration           string `json:"configuration"`
						PostConfigurationScript string `json:"post-configuration-script"`
					}{
						InfoTimestampReference: "PATHOK",
						BootImage: struct {
							DownloadURI       []string `json:"download-uri"`
							ImageVerification []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							} `json:"image-verification"`
						}{
							DownloadURI: []string{},
							ImageVerification: []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							}{{
								HashAlgorithm: "md5",
								HashValue:     "d41d8cd98f00b204e9800998ecf8427e",
							}},
						},
						PreConfigurationScript:  "",
						ConfigurationHandling:   "",
						Configuration:           "",
						PostConfigurationScript: "",
					},
				},
				BootstrapServerRedirectInfo: BootstrapServerRedirectInfo{},
			},
			wantErr: false,
		},
		{
			args: args{typeOf: "post"},
			name: "OK Case with POST",
			fields: fields{
				BootstrapURL:             "",
				SerialNumber:             "",
				DevicePassword:           "",
				DevicePrivateKey:         "",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "",
				ContentTypeReq:           "",
				InputJSONContent:         "",
				DhcpLeaseFile:            "",
				ProgressJSON:             ProgressJSON{},
				BootstrapServerOnboardingInfo: BootstrapServerOnboardingInfo{
					IetfSztpConveyedInfoOnboardingInformation: struct {
						InfoTimestampReference string
						BootImage              struct {
							DownloadURI       []string `json:"download-uri"`
							ImageVerification []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							} `json:"image-verification"`
						} `json:"boot-image"`
						PreConfigurationScript  string `json:"pre-configuration-script"`
						ConfigurationHandling   string `json:"configuration-handling"`
						Configuration           string `json:"configuration"`
						PostConfigurationScript string `json:"post-configuration-script"`
					}{
						InfoTimestampReference: "PATHOK",
						BootImage: struct {
							DownloadURI       []string `json:"download-uri"`
							ImageVerification []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							} `json:"image-verification"`
						}{
							DownloadURI: []string{},
							ImageVerification: []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							}{{
								HashAlgorithm: "md5",
								HashValue:     "d41d8cd98f00b204e9800998ecf8427e",
							}},
						},
						PreConfigurationScript:  "",
						ConfigurationHandling:   "",
						Configuration:           "",
						PostConfigurationScript: "",
					},
				},
				BootstrapServerRedirectInfo: BootstrapServerRedirectInfo{},
			},
			wantErr: false,
		},
		{
			args: args{typeOf: "post"},
			name: "OK Case with POST",
			fields: fields{
				BootstrapURL:             "",
				SerialNumber:             "",
				DevicePassword:           "",
				DevicePrivateKey:         "",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "",
				ContentTypeReq:           "",
				InputJSONContent:         "",
				DhcpLeaseFile:            "",
				ProgressJSON:             ProgressJSON{},
				BootstrapServerOnboardingInfo: BootstrapServerOnboardingInfo{
					IetfSztpConveyedInfoOnboardingInformation: struct {
						InfoTimestampReference string
						BootImage              struct {
							DownloadURI       []string `json:"download-uri"`
							ImageVerification []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							} `json:"image-verification"`
						} `json:"boot-image"`
						PreConfigurationScript  string `json:"pre-configuration-script"`
						ConfigurationHandling   string `json:"configuration-handling"`
						Configuration           string `json:"configuration"`
						PostConfigurationScript string `json:"post-configuration-script"`
					}{
						InfoTimestampReference: " ../",
						BootImage: struct {
							DownloadURI       []string `json:"download-uri"`
							ImageVerification []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							} `json:"image-verification"`
						}{
							DownloadURI: []string{},
							ImageVerification: []struct {
								HashAlgorithm string `json:"hash-algorithm"`
								HashValue     string `json:"hash-value"`
							}{{
								HashAlgorithm: "md5",
								HashValue:     "d41d8cd98f00b204e9800998ecf8427e",
							}},
						},
						PreConfigurationScript:  "",
						ConfigurationHandling:   "",
						Configuration:           "",
						PostConfigurationScript: "",
					},
				},
				BootstrapServerRedirectInfo: BootstrapServerRedirectInfo{},
			},
			wantErr: true,
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
			if err := a.launchScriptsConfiguration(tt.args.typeOf); (err != nil) != tt.wantErr {
				t.Errorf("launchScriptsConfiguration() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
