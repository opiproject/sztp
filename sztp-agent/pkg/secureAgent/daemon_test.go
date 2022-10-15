package secureAgent

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestAgent_RunCommandDaemon(t *testing.T) {
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
		name    string
		fields  fields
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
			}
			if err := a.RunCommandDaemon(); (err != nil) != tt.wantErr {
				t.Errorf("RunCommandDaemon() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAgent_getBootstrapURL(t *testing.T) {
	dhcpTestFileOK := "./test.dhcp"
	createTempTestFile(dhcpTestFileOK, true)

	type fields struct {
		BootstrapURL             string
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
			name: "Test OK Case file exists and get url successfully",
			fields: fields{
				BootstrapURL:             "http://localhost",
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
				BootstrapURL:             "http://localhost",
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
				BootstrapURL:             tt.fields.BootstrapURL,
				SerialNumber:             tt.fields.SerialNumber,
				DevicePassword:           tt.fields.DevicePassword,
				DevicePrivateKey:         tt.fields.DevicePrivateKey,
				DeviceEndEntityCert:      tt.fields.DeviceEndEntityCert,
				BootstrapTrustAnchorCert: tt.fields.BootstrapTrustAnchorCert,
				ContentTypeReq:           tt.fields.ContentTypeReq,
				InputJSONContent:         tt.fields.InputJSONContent,
				DhcpLeaseFile:            tt.fields.DhcpLeasesFile,
			}
			if err := a.getBootstrapURL(); (err != nil) != tt.wantErr {
				t.Errorf("runDaemon() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	deleteTempTestFile(dhcpTestFileOK)
}

func createTempTestFile(file string, ok bool) {
	f, err := os.Create(file)
	if err != nil {
		log.Fatal(err)
	}
	mydhcpresponse := `lease {
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

	_, err2 := f.WriteString(mydhcpresponse)

	if err2 != nil {
		log.Fatal(err2)
	}
}

func deleteTempTestFile(file string) {

	err := os.RemoveAll(file)

	if err != nil {
		fmt.Println(err)
		return
	}
}

func TestAgent_doRequestBootstrapServer(t *testing.T) {
	var output []byte
	expected := BootstrapServerPostOutput{
		IetfSztpBootstrapServerOutput: struct {
			ConveyedInformation string `json:"conveyed-information"`
		}{
			ConveyedInformation: "ZHVtbXkgZGF0YQ==",
		},
	}
	expectedFailedBase64 := BootstrapServerPostOutput{
		IetfSztpBootstrapServerOutput: struct {
			ConveyedInformation string `json:"conveyed-information"`
		}{
			ConveyedInformation: "{wrongBASE64}",
		},
	}
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		log.Println(user, pass)

		if (user + ":" + pass) == "USER:PASS" {
			w.WriteHeader(200)
			output, _ = json.Marshal(expected)
		} else if (user + ":" + pass) == "KOBASE64:KO" {
			w.WriteHeader(200)
			output, _ = json.Marshal(expectedFailedBase64)
		} else {
			w.WriteHeader(400)
			output, _ = json.Marshal(expected)
		}
		fmt.Fprintf(w, string(output))

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
			name: "Test OK passing all the information",
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
			}
			if err := a.doRequestBootstrapServer(); (err != nil) != tt.wantErr {
				t.Errorf("doRequestBootstrapServer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
