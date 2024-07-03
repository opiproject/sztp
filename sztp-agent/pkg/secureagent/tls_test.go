// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 Red Hat.

// Package secureagent implements the secure agent
package secureagent

import (
	"reflect"
	"testing"
)

func TestAgent_doTLSRequest(t *testing.T) {
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
	}
	var tests []struct {
		name    string
		fields  fields
		want    *BootstrapServerPostOutput
		wantErr bool
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
			got, err := a.doTLSRequest(a.GetInputJSONContent(), tt.fields.BootstrapURL[0], false)
			if (err != nil) != tt.wantErr {
				t.Errorf("doTLSRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("doTLSRequest() got = %v, want %v", got, tt.want)
			}
		})
	}
}
