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

	"github.com/jarcoal/httpmock"
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
func TestAgent_discoverBootstrapURLs(t *testing.T) {
	dhcpTestFileOK := "/tmp/test.dhcp"
	createTempTestFile(dhcpTestFileOK, DHCPTestContent, true)

	type fields struct {
		InputBootstrapURL        string
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
			name: "Test OK Case dhcp leases file exists and get url successfully",
			fields: fields{
				InputBootstrapURL:        "",
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
			name: "Test OK Case url given by user while leases file is not",
			fields: fields{
				InputBootstrapURL:        "http://user/given",
				SerialNumber:             "my-serial-number",
				DevicePassword:           "my-password",
				DevicePrivateKey:         "",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "",
				ContentTypeReq:           CONTENT_TYPE_YANG,
				InputJSONContent:         "",
				DhcpLeasesFile:           "",
			},
			wantErr: false,
		},
		{
			name: "Test OK Case url given by user and leases file given by user as well",
			fields: fields{
				InputBootstrapURL:        "http://user/given",
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
				InputBootstrapURL:        "",
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
				InputBootstrapURL:        tt.fields.InputBootstrapURL,
				SerialNumber:             tt.fields.SerialNumber,
				DevicePassword:           tt.fields.DevicePassword,
				DevicePrivateKey:         tt.fields.DevicePrivateKey,
				DeviceEndEntityCert:      tt.fields.DeviceEndEntityCert,
				BootstrapTrustAnchorCert: tt.fields.BootstrapTrustAnchorCert,
				ContentTypeReq:           tt.fields.ContentTypeReq,
				InputJSONContent:         tt.fields.InputJSONContent,
				DhcpLeaseFile:            tt.fields.DhcpLeasesFile,
			}
			if err := a.discoverBootstrapURLs(); (err != nil) != tt.wantErr {
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

func TestAgent_doHandleBootstrapRedirect(t *testing.T) {
	type fields struct {
		InputBootstrapURL           string
		BootstrapServerRedirectInfo BootstrapServerRedirectInfo
	}
	tests := []struct {
		name                 string
		fields               fields
		wantErr              bool
		expectedBootstrapURL string
	}{
		{
			name: "Fail test with invalid address",
			fields: fields{
				InputBootstrapURL: "",
				BootstrapServerRedirectInfo: BootstrapServerRedirectInfo{
					IetfSztpConveyedInfoRedirectInformation: struct {
						BootstrapServer []struct {
							Address     string `json:"address"`
							Port        int    `json:"port"`
							TrustAnchor string `json:"trust-anchor"`
						} `json:"bootstrap-server"`
					}{
						BootstrapServer: []struct {
							Address     string `json:"address"`
							Port        int    `json:"port"`
							TrustAnchor string `json:"trust-anchor"`
						}{{
							Address: "",
							Port:    0,
						}},
					},
				},
			},
			wantErr:              true,
			expectedBootstrapURL: "",
		},
		{
			name: "Fail test with invalid port",
			fields: fields{
				InputBootstrapURL: "",
				BootstrapServerRedirectInfo: BootstrapServerRedirectInfo{
					IetfSztpConveyedInfoRedirectInformation: struct {
						BootstrapServer []struct {
							Address     string `json:"address"`
							Port        int    `json:"port"`
							TrustAnchor string `json:"trust-anchor"`
						} `json:"bootstrap-server"`
					}{
						BootstrapServer: []struct {
							Address     string `json:"address"`
							Port        int    `json:"port"`
							TrustAnchor string `json:"trust-anchor"`
						}{{
							Address: "8.8.8.8",
							Port:    -1000,
						}},
					},
				},
			},
			wantErr:              true,
			expectedBootstrapURL: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Agent{
				BootstrapURL:                tt.fields.InputBootstrapURL,
				BootstrapServerRedirectInfo: tt.fields.BootstrapServerRedirectInfo,
			}
			if err := a.doHandleBootstrapRedirect(); (err != nil) != tt.wantErr {
				t.Errorf("doHandleBootstrapRedirect() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
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
				HttpClient:               &http.Client{},
			}
			if err := a.doRequestBootstrapServerOnboardingInfo(); (err != nil) != tt.wantErr {
				t.Errorf("doRequestBootstrapServer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

//nolint:funlen
func TestAgent_performBootstrapSequence(t *testing.T) {
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
	expectedRedirect := BootstrapServerPostOutput{
		IetfSztpBootstrapServerOutput: struct {
			ConveyedInformation string `json:"conveyed-information"`
		}{
			ConveyedInformation: "MIIDfQYLKoZIhvcNAQkQASugggNsBIIDaHsKICAiaWV0Zi1zenRwLWNvbnZleWVkLWluZm86b25ib2FyZGluZy1pbmZvcm1hdGlvbiI6IHsKICAgICJib290LWltYWdlIjogewogICAgICAiZG93bmxvYWQtdXJpIjogWwogICAgICAgICJodHRwczovL3dlYjo0NDMvc2Vjb25kLWJvb3QtaW1hZ2UuaW1nIiwKICAgICAgICAiZnRwczovL3dlYjo5OTAvc2Vjb25kLWJvb3QtaW1hZ2UuaW1nIgogICAgICBdLAogICAgICAiaW1hZ2UtdmVyaWZpY2F0aW9uIjogWwogICAgICAgIHsKICAgICAgICAgICJoYXNoLWFsZ29yaXRobSI6ICJpZXRmLXN6dHAtY29udmV5ZWQtaW5mbzpzaGEtMjU2IiwKICAgICAgICAgICJoYXNoLXZhbHVlIjogIjdiOmNhOmU2OmFjOjIzOjA2OmQ4Ojc5OjA2OjhjOmFjOjAzOjgwOmUyOjE2OjQ0OjdlOjQwOjZhOjY1OmZhOmQ0OjY5OjYxOjZlOjA1OmNlOmY1Ojg3OmRjOjJiOjk3IgogICAgICAgIH0KICAgICAgXQogICAgfSwKICAgICJwcmUtY29uZmlndXJhdGlvbi1zY3JpcHQiOiAiSXlFdlltbHVMMkpoYzJnS1pXTm9ieUFpYVc1emFXUmxJSFJvWlNCelpXTnZibVF0Y0hKbExXTnZibVpwWjNWeVlYUnBiMjR0YzJOeWFYQjBMaTR1SWdvPSIsCiAgICAiY29uZmlndXJhdGlvbi1oYW5kbGluZyI6ICJtZXJnZSIsCiAgICAiY29uZmlndXJhdGlvbiI6ICJQSFJ2Y0NCNGJXeHVjejBpYUhSMGNITTZMMlY0WVcxd2JHVXVZMjl0TDJOdmJtWnBaeUkrQ2lBZ1BHRnVlUzE0Yld3dFkyOXVkR1Z1ZEMxdmEyRjVMejRLUEM5MGIzQStDZz09IiwKICAgICJwb3N0LWNvbmZpZ3VyYXRpb24tc2NyaXB0IjogIkl5RXZZbWx1TDJKaGMyZ0taV05vYnlBaWFXNXphV1JsSUhSb1pTQnpaV052Ym1RdGNHOXpkQzFqYjI1bWFXZDFjbUYwYVc5dUxYTmpjbWx3ZEM0dUxpSUsiCiAgfQp9",
		},
	}
	expectedFailedBase64 := BootstrapServerPostOutput{
		IetfSztpBootstrapServerOutput: struct {
			ConveyedInformation string `json:"conveyed-information"`
		}{
			ConveyedInformation: "{wrongBASE64}",
		},
	}
	expectedFailedImage := BootstrapServerPostOutput{
		IetfSztpBootstrapServerOutput: struct {
			ConveyedInformation string `json:"conveyed-information"`
		}{
			ConveyedInformation: "MIIDfwYLKoZIhvcNAQkQASugggNuBIIDansKICAiaWV0Zi1zenRwLWNvbnZleWVkLWluZm86b25ib2FyZGluZy1pbmZvcm1hdGlvbiI6IHsKICAgICJib290LWltYWdlIjogewogICAgICAiZG93bmxvYWQtdXJpIjogWwogICAgICAgICJodHRwOi8vd2ViOjgwODIvdmFyL2xpYi9taXNjL215LWJvb3QtaW1hZ2UuaW1nIiwKICAgICAgICAiZnRwOi8vd2ViOjMwODIvdmFyL2xpYi9taXNjL215LWJvb3QtaW1hZ2UuaW1nIgogICAgICBdLAogICAgICAiaW1hZ2UtdmVyaWZpY2F0aW9uIjogWwogICAgICAgIHsKICAgICAgICAgICJoYXNoLWFsZ29yaXRobSI6ICJpZXRmLXN6dHAtY29udmV5ZWQtaW5mbzpzaGEtMjU2IiwKICAgICAgICAgICJoYXNoLXZhbHVlIjogIjdiOmNhOmU2OmFjOjIzOjA2OmQ4Ojc5OjA2OjhjOmFjOjAzOjgwOmUyOjE2OjQ0OjdlOjQwOjZhOjY1OmZhOmQ0OjY5OjYxOjZlOjA1OmNlOmY1Ojg3OmRjOjJiOjk3IgogICAgICAgIH0KICAgICAgXQogICAgfSwKICAgICJwcmUtY29uZmlndXJhdGlvbi1zY3JpcHQiOiAiSXlFdlltbHVMMkpoYzJnS1pXTm9ieUFpYVc1emFXUmxJSFJvWlNCd2NtVXRZMjl1Wm1sbmRYSmhkR2x2YmkxelkzSnBjSFF1TGk0aUNnPT0iLAogICAgImNvbmZpZ3VyYXRpb24taGFuZGxpbmciOiAibWVyZ2UiLAogICAgImNvbmZpZ3VyYXRpb24iOiAiUEhSdmNDQjRiV3h1Y3owaWFIUjBjSE02TDJWNFlXMXdiR1V1WTI5dEwyTnZibVpwWnlJK0NpQWdQR0Z1ZVMxNGJXd3RZMjl1ZEdWdWRDMXZhMkY1THo0S1BDOTBiM0ErQ2c9PSIsCiAgICAicG9zdC1jb25maWd1cmF0aW9uLXNjcmlwdCI6ICJJeUV2WW1sdUwySmhjMmdLWldOb2J5QWlhVzV6YVdSbElIUm9aU0J3YjNOMExXTnZibVpwWjNWeVlYUnBiMjR0YzJOeWFYQjBMaTR1SWdvPSIKICB9Cn0=",
		},
	}
	expectedFailedPreScript := BootstrapServerPostOutput{
		IetfSztpBootstrapServerOutput: struct {
			ConveyedInformation string `json:"conveyed-information"`
		}{
			ConveyedInformation: "MIIDbwYLKoZIhvcNAQkQASugggNeBIIDWnsKICAiaWV0Zi1zenRwLWNvbnZleWVkLWluZm86b25ib2FyZGluZy1pbmZvcm1hdGlvbiI6IHsKICAgICJib290LWltYWdlIjogewogICAgICAiZG93bmxvYWQtdXJpIjogWwogICAgICAgICJodHRwczovL3dlYjo0NDMvdGVzdC5pbWciLAogICAgICAgICJmdHBzOi8vd2ViOjk5MC90ZXN0LmltZyIKICAgICAgXSwKICAgICAgImltYWdlLXZlcmlmaWNhdGlvbiI6IFsKICAgICAgICB7CiAgICAgICAgICAiaGFzaC1hbGdvcml0aG0iOiAiaWV0Zi1zenRwLWNvbnZleWVkLWluZm86c2hhLTI1NiIsCiAgICAgICAgICAiaGFzaC12YWx1ZSI6ICJlMzpiMDpjNDo0Mjo5ODpmYzoxYzoxNDo5YTpmYjpmNDpjODo5OTo2ZjpiOToyNDoyNzphZTo0MTplNDo2NDo5Yjo5Mzo0YzphNDo5NTo5OToxYjo3ODo1MjpiODo1NSIKICAgICAgICB9CiAgICAgIF0KICAgIH0sCiAgICAicHJlLWNvbmZpZ3VyYXRpb24tc2NyaXB0IjogIkl5RXZZbWx1TDJKaGMyZ0taV05vYnlBaWFXNXphV1JsSUhSb1pTQjBhR2x5WkMxd2NtVXRZMjl1Wm1sbmRYSmhkR2x2YmkxelkzSnBjSFF1TGk0aUNtVnljbTl5IiwKICAgICJjb25maWd1cmF0aW9uLWhhbmRsaW5nIjogIm1lcmdlIiwKICAgICJjb25maWd1cmF0aW9uIjogIlBIUnZjQ0I0Yld4dWN6MGlhSFIwY0hNNkwyVjRZVzF3YkdVdVkyOXRMMk52Ym1acFp5SStDaUFnUEdGdWVTMTRiV3d0WTI5dWRHVnVkQzF2YTJGNUx6NEtQQzkwYjNBK0NnPT0iLAogICAgInBvc3QtY29uZmlndXJhdGlvbi1zY3JpcHQiOiAiSXlFdlltbHVMMkpoYzJnS1pXTm9ieUFpYVc1emFXUmxJSFJvWlNCMGFHbHlaQzF3YjNOMExXTnZibVpwWjNWeVlYUnBiMjR0YzJOeWFYQjBMaTR1SWdwbGNuSnZjZz09IgogIH0KfQ==",
		},
	}
	expectedFailedPostScript := BootstrapServerPostOutput{
		IetfSztpBootstrapServerOutput: struct {
			ConveyedInformation string `json:"conveyed-information"`
		}{
			ConveyedInformation: "MIIDawYLKoZIhvcNAQkQASugggNaBIIDVnsKICAiaWV0Zi1zenRwLWNvbnZleWVkLWluZm86b25ib2FyZGluZy1pbmZvcm1hdGlvbiI6IHsKICAgICJib290LWltYWdlIjogewogICAgICAiZG93bmxvYWQtdXJpIjogWwogICAgICAgICJodHRwczovL3dlYjo0NDMvdGVzdC5pbWciLAogICAgICAgICJmdHBzOi8vd2ViOjk5MC90ZXN0LmltZyIKICAgICAgXSwKICAgICAgImltYWdlLXZlcmlmaWNhdGlvbiI6IFsKICAgICAgICB7CiAgICAgICAgICAiaGFzaC1hbGdvcml0aG0iOiAiaWV0Zi1zenRwLWNvbnZleWVkLWluZm86c2hhLTI1NiIsCiAgICAgICAgICAiaGFzaC12YWx1ZSI6ICJlMzpiMDpjNDo0Mjo5ODpmYzoxYzoxNDo5YTpmYjpmNDpjODo5OTo2ZjpiOToyNDoyNzphZTo0MTplNDo2NDo5Yjo5Mzo0YzphNDo5NTo5OToxYjo3ODo1MjpiODo1NSIKICAgICAgICB9CiAgICAgIF0KICAgIH0sCiAgICAicHJlLWNvbmZpZ3VyYXRpb24tc2NyaXB0IjogIkl5RXZZbWx1TDJKaGMyZ0taV05vYnlBaWFXNXphV1JsSUhSb1pTQjBhR2x5WkMxd2NtVXRZMjl1Wm1sbmRYSmhkR2x2YmkxelkzSnBjSFF1TGk0aUNnPT0iLAogICAgImNvbmZpZ3VyYXRpb24taGFuZGxpbmciOiAibWVyZ2UiLAogICAgImNvbmZpZ3VyYXRpb24iOiAiUEhSdmNDQjRiV3h1Y3owaWFIUjBjSE02TDJWNFlXMXdiR1V1WTI5dEwyTnZibVpwWnlJK0NpQWdQR0Z1ZVMxNGJXd3RZMjl1ZEdWdWRDMXZhMkY1THo0S1BDOTBiM0ErQ2c9PSIsCiAgICAicG9zdC1jb25maWd1cmF0aW9uLXNjcmlwdCI6ICJJeUV2WW1sdUwySmhjMmdLWldOb2J5QWlhVzV6YVdSbElIUm9aU0IwYUdseVpDMXdiM04wTFdOdmJtWnBaM1Z5WVhScGIyNHRjMk55YVhCMExpNHVJZ3BsY25KdmNnbz0iCiAgfQp9",
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

	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Test KO test where discover bootstrapURL fails",
			fields: fields{
				InputBootstrapURL:             "",
				SerialNumber:                  "my-serial-number",
				DevicePassword:                "my-password",
				DevicePrivateKey:              "privateKey",
				DeviceEndEntityCert:           "endEntityCert",
				BootstrapTrustAnchorCert:      "trustAnchorCert",
				ContentTypeReq:                "application/json",
				InputJSONContent:              generateInputJSONContent(),
				DhcpLeaseFile:                 "/file/does/not/exist",
				ProgressJSON:                  ProgressJSON{},
				BootstrapServerOnboardingInfo: BootstrapServerOnboardingInfo{},
				BootstrapServerRedirectInfo:   BootstrapServerRedirectInfo{},
			},
			wantErr: true,
		},
		{
			name: "Test KO where doRequestBootstrapServerOnboardingInfo fails",
			fields: fields{
				InputBootstrapURL:        "https://bootstrap-server.com",
				SerialNumber:             "KOBASE64",
				DevicePassword:           "KO",
				DevicePrivateKey:         "",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "",
				ContentTypeReq:           "",
				InputJSONContent:         "",
				DhcpLeaseFile:            "",
				ProgressJSON:             ProgressJSON{},
				BootstrapServerOnboardingInfo: BootstrapServerOnboardingInfo{},
				BootstrapServerRedirectInfo:   BootstrapServerRedirectInfo{},
			},
			wantErr: true,
		},
		{
			name: "Test KO where doHandleBootstrapRedirect fails",
			fields: fields{
				InputBootstrapURL: "https://bootstrap-server.com",
				SerialNumber: 	"REDIRECT",
				DevicePassword: "PASS",
				BootstrapServerRedirectInfo: BootstrapServerRedirectInfo{
					IetfSztpConveyedInfoRedirectInformation: struct {
						BootstrapServer []struct {
							Address     string `json:"address"`
							Port        int    `json:"port"`
							TrustAnchor string `json:"trust-anchor"`
						} `json:"bootstrap-server"`
					}{
						BootstrapServer: []struct {
							Address     string `json:"address"`
							Port        int    `json:"port"`
							TrustAnchor string `json:"trust-anchor"`
						}{{
							Address: "",
							Port:    0,
						}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Test KO where downloadAndValidateImage fails",
			fields: fields{
				InputBootstrapURL:        "https://bootstrap-server.com",
				SerialNumber:             "KOIMAGE",
				DevicePassword:           "KO",
				DevicePrivateKey:         "",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "",
				ContentTypeReq:           "",
				InputJSONContent:         "",
				DhcpLeaseFile:            "",
				ProgressJSON:             ProgressJSON{},
				BootstrapServerOnboardingInfo: BootstrapServerOnboardingInfo{},
				BootstrapServerRedirectInfo: BootstrapServerRedirectInfo{},
			},
			wantErr: true,
		},
		{
			name: "Test KO where launchScriptsConfiguration PRE fails",
			fields: fields{
				InputBootstrapURL:        "https://bootstrap-server.com",
				SerialNumber:             "KOPRESCRIPT",
				DevicePassword:           "KO",
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
			wantErr: true,
		},
		{
			name: "Test KO where launchScriptsConfiguration POST fails",
			fields: fields{
				InputBootstrapURL:        "https://bootstrap-server.com",
				SerialNumber:             "KOPOSTSCRIPT",
				DevicePassword:           "KO",
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
			wantErr: true,
		},
		{
			name: "Test OK",
			fields: fields{
				InputBootstrapURL:        "https://bootstrap-server.com",
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
			wantErr: false,
		},
	}

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", "https://bootstrap-server.com", func(req *http.Request) (*http.Response, error) {
        user, pass, _ := req.BasicAuth()

		if (user + ":" + pass) == "USER:PASS" {
			output, _ := json.Marshal(expectedOnboarding)
			return httpmock.NewStringResponse(200, string(output)), nil
		}

		if (user + ":" + pass) == "REDIRECT:PASS" {
			output, _ := json.Marshal(expectedRedirect)
			return httpmock.NewStringResponse(200, string(output)), nil
		}

		if (user + ":" + pass) == "KOBASE64:KO" {
			output, _ := json.Marshal(expectedFailedBase64)
			return httpmock.NewStringResponse(200, string(output)), nil
		}

		if (user + ":" + pass) == "KOIMAGE:KO" {
			output, _ := json.Marshal(expectedFailedImage)
			return httpmock.NewStringResponse(200, string(output)), nil
		}

		if (user + ":" + pass) == "KOPRESCRIPT:KO" {
			output, _ := json.Marshal(expectedFailedPreScript)
			return httpmock.NewStringResponse(200, string(output)), nil
		}

		if (user + ":" + pass) == "KOPOSTSCRIPT:KO" {
			output, _ := json.Marshal(expectedFailedPostScript)
			return httpmock.NewStringResponse(200, string(output)), nil
		}

		if (user + ":" + pass) == "KO:KO" {
			output, _ := json.Marshal(expectedError)
			return httpmock.NewStringResponse(401, string(output)), nil
		}

		return httpmock.NewStringResponse(401, string("output")), nil
    })

	httpmock.RegisterResponder("GET", "https://web:443/test.img", func(req *http.Request) (*http.Response, error) {
		return httpmock.NewBytesResponse(200, []byte{}), nil
	})

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
			if err := a.performBootstrapSequence(); (err != nil) != tt.wantErr {
				t.Errorf("RunCommand() error = %v, wantErr %v", err, tt.wantErr)
			}

		})
	}
}

func TestAgent_DaemonCommand(t *testing.T) {
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

	httpmock.RegisterResponder("POST", "https://daemon-command.com", func(req *http.Request) (*http.Response, error) {
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
				InputBootstrapURL:        "https://daemon-command.com",
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
			if err := a.RunCommandDaemon(); (err != nil) != tt.wantErr {
				t.Errorf("RunCommand() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
