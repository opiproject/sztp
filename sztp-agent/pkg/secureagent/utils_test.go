package secureagent

import (
	"reflect"
	"strings"
	"testing"
)

func TestAgent_doTLSRequest(t *testing.T) {
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
		want    *BootstrapServerPostOutput
		wantErr bool
	}{
		// TODO: Add test cases.
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
			got, err := a.doTLSRequest(a.GetInputJSONContent(), a.GetBootstrapURL())
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

func Test_extractfromLine(t *testing.T) {
	type args struct {
		line  string
		regex string
		index int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test OK all fields aligned",
			args: args{
				line:  "	option sztp-redirect-urls \"https://bootstrap:9090/restconf/operations/ietf-sztp-bootstrap-server:get-bootstrapping-data\";",
				regex: `(?m)[^"]*`,
				index: 1,
			},
			want: "https://bootstrap:9090/restconf/operations/ietf-sztp-bootstrap-server:get-bootstrapping-data",
		},
		{
			name: "Test KO no match reg",
			args: args{
				line:  "ANYTHING",
				regex: `(?m)[^"]*`,
				index: 1,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractfromLine(tt.args.line, tt.args.regex, tt.args.index); got != tt.want {
				t.Errorf("extractfromLine() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_linesInFileContains(t *testing.T) {
	dhcpTestFileOK := "/tmp/test.dhcp"
	createTempTestFile(dhcpTestFileOK, true)
	type args struct {
		file   string
		substr string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test OK line in files",
			args: args{
				file:   dhcpTestFileOK,
				substr: "sztp-redirect-urls",
			},
			want: "option sztp-redirect-urls \"http://mymock/test\";",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := strings.TrimSpace(linesInFileContains(tt.args.file, tt.args.substr)); got != tt.want {
				t.Errorf("linesInFileContains() = %v, want %v", got, tt.want)
			}
		})
	}
	deleteTempTestFile(dhcpTestFileOK)
}

func Test_replaceQuotes(t *testing.T) {
	type args struct {
		input string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test remove Quotes",
			args: args{
				input: "mynew\"car",
			},
			want: "mynewcar",
		},
		{
			name: "Test ok without removing Quotes",
			args: args{
				input: "mynewcar",
			},
			want: "mynewcar",
		},
		{
			name: "Test ok without removing only Quotes",
			args: args{
				input: "\"",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := replaceQuotes(tt.args.input); got != tt.want {
				t.Errorf("replaceQuotes() = %v, want %v", got, tt.want)
			}
		})
	}
}
