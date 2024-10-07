package secureagent

import (
	"net/http"
	"testing"
)

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
				HttpClient:                    &http.Client{},
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
				HttpClient:                    &http.Client{},
			}
			if err := a.launchScriptsConfiguration(tt.args.typeOf); (err != nil) != tt.wantErr {
				t.Errorf("launchScriptsConfiguration() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
