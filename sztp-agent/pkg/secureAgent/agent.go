/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

package secureAgent

import (
	"log"
)

const (
	CONTENT_TYPE_YANG = "Content-Type:application/yang-data+json"
	OS_RELEASE_FILE   = "/etc/os-release"
)

type InputJSON struct {
	IetfSztpBootstrapServerInput struct {
		HwModel             string        `json:"hw-model"`
		OsName              string        `json:"os-name"`
		OsVersion           string        `json:"os-version"`
		SignedDataPreferred []interface{} `json:"signed-data-preferred"`
		Nonce               string        `json:"nonce"`
	} `json:"ietf-sztp-bootstrap-server:input"`
}

type BootstrapServerPostOutput struct {
	IetfSztpBootstrapServerOutput struct {
		ConveyedInformation string `json:"conveyed-information"`
	} `json:"ietf-sztp-bootstrap-server:output"`
}

//Agent is the basic structure to define an agent instance
type Agent struct {
	BootstrapURL             string //Bootstrap complete URL
	SerialNumber             string //Device's Serial Number
	DevicePassword           string //Device's Password
	DevicePrivateKey         string //Device's private key
	DeviceEndEntityCert      string //Device's end-entity cert
	BootstrapTrustAnchorCert string //the trusted bootstrap server's trust-anchor certificate (PEM)
	ContentTypeReq           string // The content type for the request to the Server
	InputJSONContent         string //The input.json file serialized
}

func NewAgent(bootstrapURL, serialNumber, devicePassword, devicePrivateKey, deviceEndEntityCert, bootstrapTrustAnchorCert string) *Agent {
	return &Agent{
		BootstrapURL:             bootstrapURL,
		SerialNumber:             serialNumber,
		DevicePassword:           devicePassword,
		DevicePrivateKey:         devicePrivateKey,
		DeviceEndEntityCert:      deviceEndEntityCert,
		BootstrapTrustAnchorCert: bootstrapTrustAnchorCert,
		ContentTypeReq:           CONTENT_TYPE_YANG,
		InputJSONContent:         GenerateInputJSONContent(),
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

func GenerateInputJSONContent() string {
	name := extractfromLine(linesInFileContains(OS_RELEASE_FILE, "NAME"), `(?m)VERSION=([^"]*)`, 0)
	log.Println("-------->" + name)
	return name
}
