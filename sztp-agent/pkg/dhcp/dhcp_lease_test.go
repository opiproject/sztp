/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// Package dhcp implements the DHCP client
package dhcp

import "testing"

func TestGetBootstrapURLViaLeaseFile(t *testing.T) {
	dhcpTestFileOK := "/tmp/test.dhcp"
	CreateTempTestFile(dhcpTestFileOK, DHCPTestContent, true)

	type fields struct {
		DhcpLeaseFile string
	}
	tests := []struct {
		name    string
		fields  fields
		want    string
		wantErr bool
	}{
		{
			name: "Test OK Case file exists and get the URL",
			fields: fields{
				DhcpLeaseFile: dhcpTestFileOK,
			},
			want:    "http://mymock/test",
			wantErr: false,
		},
		{
			name: "Test KO Case file does not exist",
			fields: fields{
				DhcpLeaseFile: "/kk/kk",
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getBootstrapURLViaLeaseFile(tt.fields.DhcpLeaseFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetBootstrapURLViaLeaseFile() error = %v, wantErr %v", err, tt.wantErr)
			} else if got != tt.want {
				t.Errorf("GetBootstrapURLViaLeaseFile() = %v, want %v", got, tt.want)
			}
		})
	}
}
