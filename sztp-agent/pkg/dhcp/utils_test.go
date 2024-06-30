/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// Package dhcp implements the DHCP client
package dhcp

import (
	"strings"
	"testing"
)

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
			if got := ExtractfromLine(tt.args.line, tt.args.regex, tt.args.index); got != tt.want {
				t.Errorf("extractfromLine() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_linesInFileContains(t *testing.T) {
	dhcpTestFileOK := "/tmp/test.dhcp"
	CreateTempTestFile(dhcpTestFileOK, DHCPTestContent, true)
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
			if got := strings.TrimSpace(LinesInFileContains(tt.args.file, tt.args.substr)); got != tt.want {
				t.Errorf("linesInFileContains() = %v, want %v", got, tt.want)
			}
		})
	}
	DeleteTempTestFile(dhcpTestFileOK)
}
