/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// nolint
// Package secureagent implements the secure agent
package secureagent

type ProgressType int64

const (
	ProgressTypeBootstrapInitiated ProgressType = iota
	ProgressTypeParsingInitiated
	ProgressTypeParsingWarning
	ProgressTypeParsingError
	ProgressTypeParsingComplete
	ProgressTypeBootImageInitiated
	ProgressTypeBootImageWarning
	ProgressTypeBootImageError
	ProgressTypeBootImageMismatch
	ProgressTypeBootImageInstalledRebooting
	ProgressTypeBootImageComplete
	ProgressTypePreScriptInitiated
	ProgressTypePreScriptWarning
	ProgressTypePreScriptError
	ProgressTypePreScriptComplete
	ProgressTypeConfigInitiated
	ProgressTypeConfigWarning
	ProgressTypeConfigError
	ProgressTypeConfigComplete
	ProgressTypePostScriptInitiated
	ProgressTypePostScriptWarning
	ProgressTypePostScriptError
	ProgressTypePostScriptComplete
	ProgressTypeBootstrapWarning
	ProgressTypeBootstrapError
	ProgressTypeBootstrapComplete
	ProgressTypeInformational
)

//nolint:funlen
func (s ProgressType) String() string {
	switch s {
	case ProgressTypeBootstrapInitiated:
		return "bootstrap-initiated"
	case ProgressTypeParsingInitiated:
		return "parsing-initiated"
	case ProgressTypeParsingWarning:
		return "parsing-warning"
	case ProgressTypeParsingError:
		return "parsing-error"
	case ProgressTypeParsingComplete:
		return "parsing-complete"
	case ProgressTypeBootImageInitiated:
		return "boot-image-initiated"
	case ProgressTypeBootImageWarning:
		return "boot-image-warning"
	case ProgressTypeBootImageError:
		return "boot-image-error"
	case ProgressTypeBootImageMismatch:
		return "boot-image-mismatch"
	case ProgressTypeBootImageInstalledRebooting:
		return "boot-image-installed-rebooting"
	case ProgressTypeBootImageComplete:
		return "boot-image-complete"
	case ProgressTypePreScriptInitiated:
		return "pre-script-initiated"
	case ProgressTypePreScriptWarning:
		return "pre-script-warning"
	case ProgressTypePreScriptError:
		return "pre-script-error"
	case ProgressTypePreScriptComplete:
		return "pre-script-complete"
	case ProgressTypeConfigInitiated:
		return "config-initiated"
	case ProgressTypeConfigWarning:
		return "config-warning"
	case ProgressTypeConfigError:
		return "config-error"
	case ProgressTypeConfigComplete:
		return "config-complete"
	case ProgressTypePostScriptInitiated:
		return "post-script-initiated"
	case ProgressTypePostScriptWarning:
		return "post-script-warning"
	case ProgressTypePostScriptError:
		return "post-script-error"
	case ProgressTypePostScriptComplete:
		return "post-script-complete"
	case ProgressTypeBootstrapWarning:
		return "bootstrap-warning"
	case ProgressTypeBootstrapError:
		return "bootstrap-error"
	case ProgressTypeBootstrapComplete:
		return "bootstrap-complete"
	case ProgressTypeInformational:
		return "informational"
	}
	return "unknown"
}

type ProgressJSON struct {
	IetfSztpBootstrapServerInput struct {
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
	} `json:"ietf-sztp-bootstrap-server:input"`
}
