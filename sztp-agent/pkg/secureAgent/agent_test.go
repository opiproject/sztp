package secureAgent

import (
	"reflect"
	"testing"
)

func TestAgent_GetBootstrapTrustAnchorCert(t *testing.T) {
	type fields struct {
		BootstrapURL             string
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
				BootstrapURL:             "test",
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
		BootstrapURL             string
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
			name: "Test get case BootstrapURL",
			fields: fields{
				BootstrapURL:             "testBootstrapURL",
				SerialNumber:             "test",
				DevicePassword:           "test",
				DevicePrivateKey:         "test",
				DeviceEndEntityCert:      "test",
				BootstrapTrustAnchorCert: "test",
				ContentTypeReq:           "test",
				InputJSONContent:         "test",
			},
			want: "testBootstrapURL",
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
			if got := a.GetBootstrapURL(); got != tt.want {
				t.Errorf("GetBootstrapURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAgent_GetContentTypeReq(t *testing.T) {
	type fields struct {
		BootstrapURL             string
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
				BootstrapURL:             "test",
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
		BootstrapURL             string
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
				BootstrapURL:             "test",
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
		BootstrapURL             string
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
				BootstrapURL:             "test",
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
		BootstrapURL             string
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
				BootstrapURL:             "test",
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
		BootstrapURL             string
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
				BootstrapURL:             "test",
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
		BootstrapURL             string
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
				BootstrapURL:             "test",
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
		BootstrapURL             string
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
				BootstrapURL:             "test",
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
		BootstrapURL             string
		SerialNumber             string
		DevicePassword           string
		DevicePrivateKey         string
		DeviceEndEntityCert      string
		BootstrapTrustAnchorCert string
		ContentTypeReq           string
		InputJSONContent         string
	}
	type args struct {
		bootstrapURL string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Test set SetBootstrapURL ",
			fields: fields{
				BootstrapURL:             "test",
				SerialNumber:             "test",
				DevicePassword:           "test",
				DevicePrivateKey:         "test",
				DeviceEndEntityCert:      "test",
				BootstrapTrustAnchorCert: "test",
				ContentTypeReq:           "test",
				InputJSONContent:         "test",
			},
			args: args{
				bootstrapURL: "bootstrapURL",
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
			if a.GetBootstrapURL() != tt.args.bootstrapURL {
				t.Errorf("SetBootstrapURL = %v, want %v", a.GetBootstrapURL(), tt.args.bootstrapURL)
			}
		})
	}
}

func TestAgent_SetContentTypeReq(t *testing.T) {
	type fields struct {
		BootstrapURL             string
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
				BootstrapURL:             "test",
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
		BootstrapURL             string
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
				BootstrapURL:             "test",
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
		BootstrapURL             string
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
				BootstrapURL:             "test",
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
		BootstrapURL             string
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
				BootstrapURL:             "test",
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
		BootstrapURL             string
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
				BootstrapURL:             "test",
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
				t.Errorf("SetBootstrapURL = %v, want %v", a.GetSerialNumber(), tt.args.serialNumber)
			}
		})
	}
}

func TestNewAgent(t *testing.T) {
	type args struct {
		bootstrapURL             string
		serialNumber             string
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
				devicePassword:           "TestDevicePassword",
				devicePrivateKey:         "TestDevicePrivateKey",
				deviceEndEntityCert:      "TestDeviceEndEntityCert",
				bootstrapTrustAnchorCert: "TestBootstrapTrustCert",
			},
			want: &Agent{
				BootstrapURL:             "TestBootstrap",
				SerialNumber:             "TestSerialNumber",
				DevicePassword:           "TestDevicePassword",
				DevicePrivateKey:         "TestDevicePrivateKey",
				DeviceEndEntityCert:      "TestDeviceEndEntityCert",
				BootstrapTrustAnchorCert: "TestBootstrapTrustCert",
				ContentTypeReq:           "application/yang-data+json",
				InputJSONContent:         generateInputJSONContent(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewAgent(tt.args.bootstrapURL, tt.args.serialNumber, tt.args.devicePassword, tt.args.devicePrivateKey, tt.args.deviceEndEntityCert, tt.args.bootstrapTrustAnchorCert); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAgent() = %v, want %v", got, tt.want)
			}
		})
	}
}
