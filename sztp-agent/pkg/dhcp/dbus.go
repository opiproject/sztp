/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// Package dhcp implements the DHCP client
package dhcp

import (
	"fmt"
	"log"

	"github.com/godbus/dbus"
)

// GetBootstrapURLsViaNetworkManager returns the sztp_redirect_urls from the active connections managed by NetworkManager
func GetBootstrapURLsViaNetworkManager() ([]string, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to system bus: %v", err)
	}

	// Get NetworkManager object
	nm := conn.Object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager")

	var activeConnPaths []dbus.ObjectPath
	err = nm.Call("org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.NetworkManager", "ActiveConnections").Store(&activeConnPaths)
	if err != nil {
		return nil, fmt.Errorf("failed to get ActiveConnections property: %v", err)
	}

	log.Println("[INFO] active connection paths: ", activeConnPaths)

	var sztpRedirectURLs []string

	// Iterate over each active connection
	for _, connPath := range activeConnPaths {
		// Get Active Connection object
		connActive := conn.Object("org.freedesktop.NetworkManager", connPath)

		// Get Dhcp4Config property from Active Connection object
		var dhcpPath dbus.ObjectPath
		err = connActive.Call("org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.NetworkManager.Connection.Active", "Dhcp4Config").Store(&dhcpPath)
		if err != nil {
			log.Println("[INFO] Dhcp4Config is not available for connection:", connPath, err)
			continue
		}

		// Get Options property from DHCP4Config object
		dhcp := conn.Object("org.freedesktop.NetworkManager", dhcpPath)
		var options map[string]dbus.Variant
		err = dhcp.Call("org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.NetworkManager.DHCP4Config", "Options").Store(&options)
		if err != nil {
			log.Println("[INFO] failed to get Options property for connection:", connPath, err)
			continue
		}

		// Logging options
		log.Println("[INFO] Options for connection:", connPath, ": ", options)

		// Check if sztp_redirect_urls option exists and append
		if variant, ok := options[SZTP_REDIRECT_URLs]; ok {
			url := variant.Value().(string)
			log.Println("sztp_redirect_url found for connection:", connPath, ": ", url)
			sztpRedirectURLs = append(sztpRedirectURLs, url)
		}
	}

	return sztpRedirectURLs, nil
}
