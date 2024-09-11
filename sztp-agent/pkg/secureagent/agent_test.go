/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// Package secureagent implements the secure agent
package secureagent

import (
	"reflect"
	"testing"
)

func TestAgent_GetBootstrapTrustAnchorCert(t *testing.T) {
	type fields struct {
		BootstrapURL             []string
		SerialNumber             string
		DevicePassword           string
		DevicePrivateKey         string
		DeviceEndEntityCert      string
		BootstrapTrustAnchorCert string
		ContentTypeReq           string
		InputJSONContent         string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Test get case BootstrapTrustAnchorCert",
			fields: fields{
				BootstrapURL:             []string{"test"},
				SerialNumber:             "test",
				DevicePassword:           "test",
				DevicePrivateKey:         "test",
				DeviceEndEntityCert:      "test",
				BootstrapTrustAnchorCert: "testBootstrapTrustAnchorCert",
				ContentTypeReq:           "test",
				InputJSONContent:         "test",
			},
			want: "testBootstrapTrustAnchorCert",
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
			}
			if got := a.GetBootstrapTrustAnchorCert(); got != tt.want {
				t.Errorf("GetBootstrapTrustAnchorCert() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAgent_GetBootstrapURL(t *testing.T) {
	type fields struct {
		BootstrapURL             []string
		SerialNumber             string
		DevicePassword           string
		DevicePrivateKey         string
		DeviceEndEntityCert      string
		BootstrapTrustAnchorCert string
		ContentTypeReq           string
		InputJSONContent         string
	}
	tests := []struct {
		name   string
		fields fields
		want   []string
	}{
		{
			name: "Test get case BootstrapURL",
			fields: fields{
				BootstrapURL:             []string{"testBootstrapURL"},
				SerialNumber:             "test",
				DevicePassword:           "test",
				DevicePrivateKey:         "test",
				DeviceEndEntityCert:      "test",
				BootstrapTrustAnchorCert: "test",
				ContentTypeReq:           "test",
				InputJSONContent:         "test",
			},
			want: []string{"testBootstrapURL"},
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
			}
			if !reflect.DeepEqual(a.GetBootstrapURL(), tt.want) {
				t.Errorf("GetBootstrapURL() = %v, want %v", a.GetBootstrapURL(), tt.want)
			}
		})
	}
}

func TestAgent_GetContentTypeReq(t *testing.T) {
	type fields struct {
		BootstrapURL             []string
		SerialNumber             string
		DevicePassword           string
		DevicePrivateKey         string
		DeviceEndEntityCert      string
		BootstrapTrustAnchorCert string
		ContentTypeReq           string
		InputJSONContent         string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Test get ContentTypeReq ",
			fields: fields{
				BootstrapURL:             []string{"test"},
				SerialNumber:             "test",
				DevicePassword:           "test",
				DevicePrivateKey:         "test",
				DeviceEndEntityCert:      "test",
				BootstrapTrustAnchorCert: "test",
				ContentTypeReq:           "application/yang-data+json",
				InputJSONContent:         "test",
			},
			want: "application/yang-data+json",
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
			}
			if got := a.GetContentTypeReq(); got != tt.want {
				t.Errorf("GetContentTypeReq() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAgent_GetDeviceEndEntityCert(t *testing.T) {
	type fields struct {
		BootstrapURL             []string
		SerialNumber             string
		DevicePassword           string
		DevicePrivateKey         string
		DeviceEndEntityCert      string
		BootstrapTrustAnchorCert string
		ContentTypeReq           string
		InputJSONContent         string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Test get GetDeviceEndEntityCert ",
			fields: fields{
				BootstrapURL:             []string{"test"},
				SerialNumber:             "test",
				DevicePassword:           "test",
				DevicePrivateKey:         "test",
				DeviceEndEntityCert:      "testDeviceEndEntityCert",
				BootstrapTrustAnchorCert: "test",
				ContentTypeReq:           "test",
				InputJSONContent:         "test",
			},
			want: "testDeviceEndEntityCert",
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
			}
			if got := a.GetDeviceEndEntityCert(); got != tt.want {
				t.Errorf("GetDeviceEndEntityCert() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAgent_GetDevicePassword(t *testing.T) {
	type fields struct {
		BootstrapURL             []string
		SerialNumber             string
		DevicePassword           string
		DevicePrivateKey         string
		DeviceEndEntityCert      string
		BootstrapTrustAnchorCert string
		ContentTypeReq           string
		InputJSONContent         string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Test get GetDevicePassword ",
			fields: fields{
				BootstrapURL:             []string{"test"},
				SerialNumber:             "test",
				DevicePassword:           "testDevicePassword",
				DevicePrivateKey:         "test",
				DeviceEndEntityCert:      "",
				BootstrapTrustAnchorCert: "test",
				ContentTypeReq:           "test",
				InputJSONContent:         "test",
			},
			want: "testDevicePassword",
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
			}
			if got := a.GetDevicePassword(); got != tt.want {
				t.Errorf("GetDevicePassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAgent_GetDevicePrivateKey(t *testing.T) {
	type fields struct {
		BootstrapURL             []string
		SerialNumber             string
		DevicePassword           string
		DevicePrivateKey         string
		DeviceEndEntityCert      string
		BootstrapTrustAnchorCert string
		ContentTypeReq           string
		InputJSONContent         string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Test get GetDevicePrivateKey ",
			fields: fields{
				BootstrapURL:             []string{"test"},
				SerialNumber:             "test",
				DevicePassword:           "test",
				DevicePrivateKey:         "testDevicePrivateKey",
				DeviceEndEntityCert:      "test",
				BootstrapTrustAnchorCert: "test",
				ContentTypeReq:           "test",
				InputJSONContent:         "test",
			},
			want: "testDevicePrivateKey",
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
			}
			if got := a.GetDevicePrivateKey(); got != tt.want {
				t.Errorf("GetDevicePrivateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAgent_GetInputJSONContent(t *testing.T) {
	type fields struct {
		BootstrapURL             []string
		SerialNumber             string
		DevicePassword           string
		DevicePrivateKey         string
		DeviceEndEntityCert      string
		BootstrapTrustAnchorCert string
		ContentTypeReq           string
		InputJSONContent         string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Test get GetInputJsonContent ",
			fields: fields{
				BootstrapURL:             []string{"test"},
				SerialNumber:             "test",
				DevicePassword:           "test",
				DevicePrivateKey:         "test",
				DeviceEndEntityCert:      "test",
				BootstrapTrustAnchorCert: "test",
				ContentTypeReq:           "test",
				InputJSONContent:         "testInputJson",
			},
			want: "testInputJson",
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
			}
			if got := a.GetInputJSONContent(); got != tt.want {
				t.Errorf("GetInputJSONContent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAgent_GetSerialNumber(t *testing.T) {
	type fields struct {
		BootstrapURL             []string
		SerialNumber             string
		DevicePassword           string
		DevicePrivateKey         string
		DeviceEndEntityCert      string
		BootstrapTrustAnchorCert string
		ContentTypeReq           string
		InputJSONContent         string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Test get GetSerialNumber ",
			fields: fields{
				BootstrapURL:             []string{"test"},
				SerialNumber:             "testSerialNumber",
				DevicePassword:           "test",
				DevicePrivateKey:         "test",
				DeviceEndEntityCert:      "test",
				BootstrapTrustAnchorCert: "test",
				ContentTypeReq:           "test",
				InputJSONContent:         "test",
			},
			want: "testSerialNumber",
		},
		{
			name: "Test SMBIOS GetSerialNumber ",
			fields: fields{
				BootstrapURL:             []string{"test"},
				SerialNumber:             "",
				DevicePassword:           "test",
				DevicePrivateKey:         "test",
				DeviceEndEntityCert:      "test",
				BootstrapTrustAnchorCert: "test",
				ContentTypeReq:           "test",
				InputJSONContent:         "test",
			},
			want: "",
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
			}
			if got := a.GetSerialNumber(); got != tt.want {
				t.Errorf("GetSerialNumber() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAgent_SetBootstrapTrustAnchorCert(t *testing.T) {
	type fields struct {
		BootstrapURL             []string
		SerialNumber             string
		DevicePassword           string
		DevicePrivateKey         string
		DeviceEndEntityCert      string
		BootstrapTrustAnchorCert string
		ContentTypeReq           string
		InputJSONContent         string
	}
	type args struct {
		cacert string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Test set SetDeviceEndEntityCert ",
			fields: fields{
				BootstrapURL:             []string{"test"},
				SerialNumber:             "test",
				DevicePassword:           "test",
				DevicePrivateKey:         "test",
				DeviceEndEntityCert:      "test",
				BootstrapTrustAnchorCert: "test",
				ContentTypeReq:           "test",
				InputJSONContent:         "test",
			},
			args: args{
				cacert: "cacertTest",
			},
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
			}
			a.SetBootstrapTrustAnchorCert(tt.args.cacert)
			if a.GetBootstrapTrustAnchorCert() != tt.args.cacert {
				t.Errorf("SetBootstrapTrustAnchorCert = %v, want %v", a.GetBootstrapTrustAnchorCert(), tt.args.cacert)
			}
		})
	}
}

func TestAgent_SetBootstrapURL(t *testing.T) {
	type fields struct {
		BootstrapURL             []string
		SerialNumber             string
		DevicePassword           string
		DevicePrivateKey         string
		DeviceEndEntityCert      string
		BootstrapTrustAnchorCert string
		ContentTypeReq           string
		InputJSONContent         string
	}
	type args struct {
		bootstrapURL []string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Test set SetBootstrapURL ",
			fields: fields{
				BootstrapURL:             []string{"test"},
				SerialNumber:             "test",
				DevicePassword:           "test",
				DevicePrivateKey:         "test",
				DeviceEndEntityCert:      "test",
				BootstrapTrustAnchorCert: "test",
				ContentTypeReq:           "test",
				InputJSONContent:         "test",
			},
			args: args{
				bootstrapURL: []string{"bootstrapURL"},
			},
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
			}
			a.SetBootstrapURL(tt.args.bootstrapURL)
			if !reflect.DeepEqual(a.GetBootstrapURL(), tt.args.bootstrapURL) {
				t.Errorf("SetBootstrapURL = %v, want %v", a.GetBootstrapURL(), tt.args.bootstrapURL)
			}
		})
	}
}

func TestAgent_SetContentTypeReq(t *testing.T) {
	type fields struct {
		BootstrapURL             []string
		SerialNumber             string
		DevicePassword           string
		DevicePrivateKey         string
		DeviceEndEntityCert      string
		BootstrapTrustAnchorCert string
		ContentTypeReq           string
		InputJSONContent         string
	}
	type args struct {
		contentType string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Test set setContentType ",
			fields: fields{
				BootstrapURL:             []string{"test"},
				SerialNumber:             "test",
				DevicePassword:           "test",
				DevicePrivateKey:         "test",
				DeviceEndEntityCert:      "test",
				BootstrapTrustAnchorCert: "test",
				ContentTypeReq:           "test",
				InputJSONContent:         "test",
			},
			args: args{
				contentType: "contentTypeNew",
			},
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
			}
			a.SetContentTypeReq(tt.args.contentType)
			if a.GetContentTypeReq() != tt.args.contentType {
				t.Errorf("SetContentType = %v, want %v", a.GetContentTypeReq(), tt.args.contentType)
			}
		})
	}
}

func TestAgent_SetDeviceEndEntityCert(t *testing.T) {
	type fields struct {
		BootstrapURL             []string
		SerialNumber             string
		DevicePassword           string
		DevicePrivateKey         string
		DeviceEndEntityCert      string
		BootstrapTrustAnchorCert string
		ContentTypeReq           string
		InputJSONContent         string
	}
	type args struct {
		deviceEndEntityCert string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Test set SetDeviceEndEntityCert ",
			fields: fields{
				BootstrapURL:             []string{"test"},
				SerialNumber:             "test",
				DevicePassword:           "test",
				DevicePrivateKey:         "test",
				DeviceEndEntityCert:      "test",
				BootstrapTrustAnchorCert: "test",
				ContentTypeReq:           "test",
				InputJSONContent:         "test",
			},
			args: args{
				deviceEndEntityCert: "deviceEndEntityCert",
			},
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
			}
			a.SetDeviceEndEntityCert(tt.args.deviceEndEntityCert)
			if a.GetDeviceEndEntityCert() != tt.args.deviceEndEntityCert {
				t.Errorf("SetDeviceEntityCert = %v, want %v", a.GetDeviceEndEntityCert(), tt.args.deviceEndEntityCert)
			}
		})
	}
}

func TestAgent_SetDevicePassword(t *testing.T) {
	type fields struct {
		BootstrapURL             []string
		SerialNumber             string
		DevicePassword           string
		DevicePrivateKey         string
		DeviceEndEntityCert      string
		BootstrapTrustAnchorCert string
		ContentTypeReq           string
		InputJSONContent         string
	}
	type args struct {
		devicePassword string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Test set SetDevicePassword ",
			fields: fields{
				BootstrapURL:             []string{"test"},
				SerialNumber:             "test",
				DevicePassword:           "test",
				DevicePrivateKey:         "test",
				DeviceEndEntityCert:      "test",
				BootstrapTrustAnchorCert: "test",
				ContentTypeReq:           "test",
				InputJSONContent:         "test",
			},
			args: args{
				devicePassword: "devicePassword",
			},
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
			}
			a.SetDevicePassword(tt.args.devicePassword)
			if a.GetDevicePassword() != tt.args.devicePassword {
				t.Errorf("SetDevicePassword = %v, want %v", a.GetDevicePassword(), tt.args.devicePassword)
			}
		})
	}
}

func TestAgent_SetDevicePrivateKey(t *testing.T) {
	type fields struct {
		BootstrapURL             []string
		SerialNumber             string
		DevicePassword           string
		DevicePrivateKey         string
		DeviceEndEntityCert      string
		BootstrapTrustAnchorCert string
		ContentTypeReq           string
		InputJSONContent         string
	}
	type args struct {
		devicePrivateKey string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Test set GetBootstrapURL ",
			fields: fields{
				BootstrapURL:             []string{"test"},
				SerialNumber:             "test",
				DevicePassword:           "test",
				DevicePrivateKey:         "test",
				DeviceEndEntityCert:      "test",
				BootstrapTrustAnchorCert: "test",
				ContentTypeReq:           "test",
				InputJSONContent:         "test",
			},
			args: args{
				devicePrivateKey: "devicePrivateKey",
			},
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
			}
			a.SetDevicePrivateKey(tt.args.devicePrivateKey)
			if a.GetDevicePrivateKey() != tt.args.devicePrivateKey {
				t.Errorf("SetDevicePRivateKey = %v, want %v", a.GetDevicePrivateKey(), tt.args.devicePrivateKey)
			}
		})
	}
}

func TestAgent_SetSerialNumber(t *testing.T) {
	type fields struct {
		BootstrapURL             []string
		SerialNumber             string
		DevicePassword           string
		DevicePrivateKey         string
		DeviceEndEntityCert      string
		BootstrapTrustAnchorCert string
		ContentTypeReq           string
		InputJSONContent         string
	}
	type args struct {
		serialNumber string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Test set setSerialnumber ",
			fields: fields{
				BootstrapURL:             []string{"test"},
				SerialNumber:             "test",
				DevicePassword:           "test",
				DevicePrivateKey:         "test",
				DeviceEndEntityCert:      "test",
				BootstrapTrustAnchorCert: "test",
				ContentTypeReq:           "test",
				InputJSONContent:         "test",
			},
			args: args{
				serialNumber: "serialNumber",
			},
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
			}
			a.SetSerialNumber(tt.args.serialNumber)
			if a.GetSerialNumber() != tt.args.serialNumber {
				t.Errorf("SetSerialNumber = %v, want %v", a.GetSerialNumber(), tt.args.serialNumber)
			}
		})
	}
}

func TestNewAgent(t *testing.T) {
	type args struct {
		bootstrapURL             string
		serialNumber             string
		dhcpLeaseFile            string
		devicePassword           string
		devicePrivateKey         string
		deviceEndEntityCert      string
		bootstrapTrustAnchorCert string
	}
	tests := []struct {
		name string
		args args
		want *Agent
	}{
		{
			name: "Test Constructor",
			args: args{
				bootstrapURL:             "TestBootstrap",
				serialNumber:             "TestSerialNumber",
				dhcpLeaseFile:            "TestDhcpLeaseFile",
				devicePassword:           "TestDevicePassword",
				devicePrivateKey:         "TestDevicePrivateKey",
				deviceEndEntityCert:      "TestDeviceEndEntityCert",
				bootstrapTrustAnchorCert: "TestBootstrapTrustCert",
			},
			want: &Agent{
				InputBootstrapURL:        "TestBootstrap",
				BootstrapURL:             []string{""},
				SerialNumber:             "TestSerialNumber",
				DevicePassword:           "TestDevicePassword",
				DevicePrivateKey:         "TestDevicePrivateKey",
				DeviceEndEntityCert:      "TestDeviceEndEntityCert",
				BootstrapTrustAnchorCert: "TestBootstrapTrustCert",
				ContentTypeReq:           "application/yang-data+json",
				InputJSONContent:         generateInputJSONContent(),
				DhcpLeaseFile:            "TestDhcpLeaseFile",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewAgent(tt.args.bootstrapURL, tt.args.serialNumber, tt.args.dhcpLeaseFile, tt.args.devicePassword, tt.args.devicePrivateKey, tt.args.deviceEndEntityCert, tt.args.bootstrapTrustAnchorCert); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAgent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAgent_GetProgressJson(t *testing.T) {
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
		name   string
		fields fields
		want   ProgressJSON
	}{
		{
			name: "Test GetProgressJson",
			fields: fields{
				BootstrapURL:             []string{"test"},
				SerialNumber:             "test",
				DevicePassword:           "test",
				DevicePrivateKey:         "test",
				DeviceEndEntityCert:      "test",
				BootstrapTrustAnchorCert: "test",
				ContentTypeReq:           "test",
				InputJSONContent:         "test",
				DhcpLeaseFile:            "test",
				ProgressJSON: ProgressJSON{
					IetfSztpBootstrapServerInput: struct {
						ProgressType string `json:"progress-type"`
						Message      string `json:"message"`
						SSHHostKeys  struct {
							SSHHostKey []struct {
								Algorithm string `json:"algorithm"`
								KeyData   string `json:"key-data"`
							} `json:"ssh-host-key,omitempty"`
						} `json:"ssh-host-keys,omitempty"`
						TrustAnchorCerts struct {
							TrustAnchorCert []string `json:"trust-anchor-cert,omitempty"`
						} `json:"trust-anchor-certs,omitempty"`
					}{
						ProgressType: "test",
						Message:      "test",
					},
				},
			},
			want: ProgressJSON{
				IetfSztpBootstrapServerInput: struct {
					ProgressType string `json:"progress-type"`
					Message      string `json:"message"`
					SSHHostKeys  struct {
						SSHHostKey []struct {
							Algorithm string `json:"algorithm"`
							KeyData   string `json:"key-data"`
						} `json:"ssh-host-key,omitempty"`
					} `json:"ssh-host-keys,omitempty"`
					TrustAnchorCerts struct {
						TrustAnchorCert []string `json:"trust-anchor-cert,omitempty"`
					} `json:"trust-anchor-certs,omitempty"`
				}{
					ProgressType: "test",
					Message:      "test",
				},
			},
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
			if got := a.GetProgressJSON(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetProgressJson() = %v, want %v", got, tt.want)
			}
		})
	}
}

// nolint:funlen
func TestAgent_SetProgressJson(t *testing.T) {
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
	type args struct {
		p ProgressJSON
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Test SetProgressJson",
			fields: fields{
				BootstrapURL:             []string{"test"},
				SerialNumber:             "test",
				DevicePassword:           "test",
				DevicePrivateKey:         "test",
				DeviceEndEntityCert:      "test",
				BootstrapTrustAnchorCert: "test",
				ContentTypeReq:           "test",
				InputJSONContent:         "test",
				DhcpLeaseFile:            "test",
				ProgressJSON: ProgressJSON{
					IetfSztpBootstrapServerInput: struct {
						ProgressType string `json:"progress-type"`
						Message      string `json:"message"`
						SSHHostKeys  struct {
							SSHHostKey []struct {
								Algorithm string `json:"algorithm"`
								KeyData   string `json:"key-data"`
							} `json:"ssh-host-key,omitempty"`
						} `json:"ssh-host-keys,omitempty"`
						TrustAnchorCerts struct {
							TrustAnchorCert []string `json:"trust-anchor-cert,omitempty"`
						} `json:"trust-anchor-certs,omitempty"`
					}{
						ProgressType: "test",
						Message:      "test",
					},
				},
			},
			args: args{
				p: ProgressJSON{
					IetfSztpBootstrapServerInput: struct {
						ProgressType string `json:"progress-type"`
						Message      string `json:"message"`
						SSHHostKeys  struct {
							SSHHostKey []struct {
								Algorithm string `json:"algorithm"`
								KeyData   string `json:"key-data"`
							} `json:"ssh-host-key,omitempty"`
						} `json:"ssh-host-keys,omitempty"`
						TrustAnchorCerts struct {
							TrustAnchorCert []string `json:"trust-anchor-cert,omitempty"`
						} `json:"trust-anchor-certs,omitempty"`
					}{
						ProgressType: "testNew",
						Message:      "testNew",
					},
				},
			},
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
			a.SetProgressJSON(tt.args.p)
			if !reflect.DeepEqual(a.GetProgressJSON(), tt.args.p) {
				t.Errorf("SetProgressJson = %v, want %v", a.GetProgressJSON(), tt.args.p)
			}
		})
	}
}

// nolint:funlen
func TestProgressType_String(t *testing.T) {
	tests := []struct {
		name string
		s    ProgressType
		want string
	}{
		{
			name: "Test ProgressType String",
			s:    ProgressType(0),
			want: "bootstrap-initiated",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(1),
			want: "parsing-initiated",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(2),
			want: "parsing-warning",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(3),
			want: "parsing-error",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(4),
			want: "parsing-complete",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(5),
			want: "boot-image-initiated",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(6),
			want: "boot-image-warning",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(7),
			want: "boot-image-error",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(8),
			want: "boot-image-mismatch",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(9),
			want: "boot-image-installed-rebooting",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(10),
			want: "boot-image-complete",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(11),
			want: "pre-script-initiated",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(12),
			want: "pre-script-warning",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(13),
			want: "pre-script-error",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(14),
			want: "pre-script-complete",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(15),
			want: "config-initiated",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(16),
			want: "config-warning",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(17),
			want: "config-error",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(18),
			want: "config-complete",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(19),
			want: "post-script-initiated",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(20),
			want: "post-script-warning",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(21),
			want: "post-script-error",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(22),
			want: "post-script-complete",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(23),
			want: "bootstrap-warning",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(24),
			want: "bootstrap-error",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(25),
			want: "bootstrap-complete",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(26),
			want: "informational",
		},
		{
			name: "Test ProgressType String",
			s:    ProgressType(27),
			want: "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}
