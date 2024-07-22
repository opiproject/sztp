/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// nolint
// Package secureagent implements the secure agent
package secureagent

const (
	CONTENT_TYPE_YANG = "application/yang-data+json"
	OS_RELEASE_FILE   = "/etc/os-release"
	SZTP_REDIRECT_URL = "sztp-redirect-urls"
	ARTIFACTS_PATH    = "/tmp/"
)

type InputJSON struct {
	IetfSztpBootstrapServerInput struct {
		HwModel   string `json:"hw-model"`
		OsName    string `json:"os-name"`
		OsVersion string `json:"os-version"`
		Nonce     string `json:"nonce"`
	} `json:"ietf-sztp-bootstrap-server:input"`
}

type BootstrapServerRedirectInfo struct {
	IetfSztpConveyedInfoRedirectInformation struct {
		BootstrapServer []struct {
			Address     string `json:"address"`
			Port        int    `json:"port"`
			TrustAnchor string `json:"trust-anchor"`
		} `json:"bootstrap-server"`
	} `json:"ietf-sztp-conveyed-info:redirect-information"`
}

type BootstrapServerOnboardingInfo struct {
	IetfSztpConveyedInfoOnboardingInformation struct {
		InfoTimestampReference string // [not received in json] This is the reference to know exactly the time file downloaded and reference to the artifacts of a specific request
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
	} `json:"ietf-sztp-conveyed-info:onboarding-information"`
}

type BootstrapServerPostOutput struct {
	IetfSztpBootstrapServerOutput struct {
		ConveyedInformation string `json:"conveyed-information"`
	} `json:"ietf-sztp-bootstrap-server:output"`
}

type BootstrapServerErrorOutput struct {
	IetfRestconfErrors struct {
		Error []struct {
			ErrorType    string `json:"error-type"`
			ErrorTag     string `json:"error-tag"`
			ErrorMessage string `json:"error-message"`
		} `json:"error"`
	} `json:"ietf-restconf:errors"`
}

// Agent is the basic structure to define an agent instance
type Agent struct {
	InputBootstrapURL             string                        // Bootstrap complete URL given by USER
	BootstrapURL                  string                        // Bootstrap complete URL
	SerialNumber                  string                        // Device's Serial Number
	DevicePassword                string                        // Device's Password
	DevicePrivateKey              string                        // Device's private key
	DeviceEndEntityCert           string                        // Device's end-entity cert
	BootstrapTrustAnchorCert      string                        // the trusted bootstrap server's trust-anchor certificate (PEM)
	ContentTypeReq                string                        // The content type for the request to the Server
	InputJSONContent              string                        // The input.json file serialized
	DhcpLeaseFile                 string                        // The dhcpfile
	ProgressJSON                  ProgressJSON                  // ProgressJson structure
	BootstrapServerOnboardingInfo BootstrapServerOnboardingInfo // BootstrapServerOnboardingInfo structure
	BootstrapServerRedirectInfo   BootstrapServerRedirectInfo   // BootstrapServerRedirectInfo structure

}

func NewAgent(bootstrapURL, serialNumber, dhcpLeaseFile, devicePassword, devicePrivateKey, deviceEndEntityCert, bootstrapTrustAnchorCert string) *Agent {
	return &Agent{
		InputBootstrapURL:             bootstrapURL,
		BootstrapURL:                  "",
		SerialNumber:                  GetSerialNumber(serialNumber),
		DevicePassword:                devicePassword,
		DevicePrivateKey:              devicePrivateKey,
		DeviceEndEntityCert:           deviceEndEntityCert,
		BootstrapTrustAnchorCert:      bootstrapTrustAnchorCert,
		ContentTypeReq:                CONTENT_TYPE_YANG,
		InputJSONContent:              generateInputJSONContent(),
		DhcpLeaseFile:                 dhcpLeaseFile,
		ProgressJSON:                  ProgressJSON{},
		BootstrapServerRedirectInfo:   BootstrapServerRedirectInfo{},
		BootstrapServerOnboardingInfo: BootstrapServerOnboardingInfo{},
	}
}

func (a *Agent) GetBootstrapURL() string {
	return a.BootstrapURL
}

func (a *Agent) GetSerialNumber() string {
	return a.SerialNumber
}

func (a *Agent) GetDevicePassword() string {
	return a.DevicePassword
}

func (a *Agent) GetDevicePrivateKey() string {
	return a.DevicePrivateKey
}

func (a *Agent) GetDeviceEndEntityCert() string {
	return a.DeviceEndEntityCert
}

func (a *Agent) GetBootstrapTrustAnchorCert() string {
	return a.BootstrapTrustAnchorCert
}

func (a *Agent) GetContentTypeReq() string {
	return a.ContentTypeReq
}

func (a *Agent) GetInputJSONContent() string {
	return a.InputJSONContent
}

func (a *Agent) GetProgressJSON() ProgressJSON {
	return a.ProgressJSON
}

func (a *Agent) SetBootstrapURL(url string) {
	a.BootstrapURL = url
}

func (a *Agent) SetSerialNumber(serialNumber string) {
	a.SerialNumber = serialNumber
}

func (a *Agent) SetDevicePassword(pass string) {
	a.DevicePassword = pass
}

func (a *Agent) SetDevicePrivateKey(key string) {
	a.DevicePrivateKey = key
}

func (a *Agent) SetDeviceEndEntityCert(cert string) {
	a.DeviceEndEntityCert = cert
}

func (a *Agent) SetBootstrapTrustAnchorCert(cacert string) {
	a.BootstrapTrustAnchorCert = cacert
}

func (a *Agent) SetContentTypeReq(ct string) {
	a.ContentTypeReq = ct
}

func (a *Agent) SetProgressJSON(p ProgressJSON) {
	a.ProgressJSON = p
}
