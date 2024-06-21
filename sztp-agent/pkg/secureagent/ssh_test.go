// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 Red Hat.
package secureagent

import (
	"reflect"
	"testing"
)

func Test_readSSHHostKeyPublicFiles(t *testing.T) {
	type args struct {
		file      string
		content   string
		Algorithm string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test OK line in files no comment",
			args: args{
				file:      "/tmp/test.pub",
				content:   "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID0mjQXlOvkM2HO5vTrSOdHOl3BGOqDiHrx8yYdbP8xR",
				Algorithm: "ssh-ed25519",
			},
			want: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID0mjQXlOvkM2HO5vTrSOdHOl3BGOqDiHrx8yYdbP8xR",
		},
		{
			name: "Test OK line in files with comment",
			args: args{
				file:      "/tmp/test.pub",
				content:   "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID0mjQXlOvkM2HO5vTrSOdHOl3BGOqDiHrx8yYdbP8xR comment",
				Algorithm: "ssh-ed25519",
			},
			want: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID0mjQXlOvkM2HO5vTrSOdHOl3BGOqDiHrx8yYdbP8xR",
		},
		{
			name: "Test too many parts in file",
			args: args{
				file:      "/tmp/test.pub",
				content:   "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID0mjQXlOvkM2HO5vTrSOdHOl3BGOqDiHrx8yYdbP8xR comment error",
				Algorithm: "ssh-ed25519",
			},
			want: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID0mjQXlOvkM2HO5vTrSOdHOl3BGOqDiHrx8yYdbP8xR",
		},
		{
			name: "Test not enough parts in file",
			args: args{
				file:    "/tmp/test.pub",
				content: "ssh-ed25519",
			},
			want: "ssh-ed25519",
		},
		{
			name: "Test file doesn't exist",
			args: args{
				file:    "/tmp/test.pub",
				content: "",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.args.content != "" {
				createTempTestFile(tt.args.file, tt.args.content, true)
			}
			for _, key := range readSSHHostKeyPublicFiles(tt.args.file) {
				if got := getSSHHostKeyString(key, true); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("readSSHHostKeyPublicFiles() - got: %v, want %v", got, tt.want)
				}
			}
			deleteTempTestFile(tt.args.file)
		})
	}
}
