/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

package secureAgent

//Agent is the basic structure to define an agent instance
type Agent struct {
	BootstrapURL             string //Bootstrap complete URL
	SerialNumber             string //Device's Serial Number
	DevicePassword           string //Device's Password
	DevicePrivateKey         string //Device's private key
	DeviceEndEntityCert      string //Device's end-entity cert
	BootstrapTrustAnchorCert string //the trusted bootstrap server's trust-anchor certificate (PEM)
}

func NewAgent(bootstrapURL, serialNumber, devicePassword, devicePrivateKey, deviceEndEntityCert, bootstrapTrustAnchorCert string) *Agent {
	return &Agent{
		BootstrapURL:             bootstrapURL,
		SerialNumber:             serialNumber,
		DevicePassword:           devicePassword,
		DevicePrivateKey:         devicePrivateKey,
		DeviceEndEntityCert:      deviceEndEntityCert,
		BootstrapTrustAnchorCert: bootstrapTrustAnchorCert,
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
