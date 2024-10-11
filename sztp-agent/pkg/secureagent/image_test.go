package secureagent

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

//nolint:funlen
func TestAgent_downloadAndValidateImage(t *testing.T) {
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/imageOK" || r.URL.Path == "/report-progress" {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(400)
		}
	}))
	defer svr.Close()

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
			name: "error writing file",
			fields: fields{
				BootstrapURL:             []string{""},
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
				BootstrapURL:             []string{""},
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
				BootstrapURL:             []string{""},
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
				BootstrapURL:             []string{""},
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
				BootstrapURL:             []string{""},
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
				HttpClient:                    &http.Client{},
			}
			if err := a.downloadAndValidateImage(&tt.fields.BootstrapURL[0]); (err != nil) != tt.wantErr {
				t.Errorf("downloadAndValidateImage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
