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

	"github.com/godbus/dbus/v5"
)

// GetBootstrapURLViaNetworkManager returns the sztp redirect URL via NetworkManager
func GetBootstrapURLViaNetworkManager() (string, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return "", fmt.Errorf("failed to connect to system bus: %v", err)
	}

	nm := conn.Object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager")

	var activeConnections []dbus.ObjectPath
	err = nm.Call("org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.NetworkManager", "ActiveConnections").Store(&activeConnections)
	if err != nil {
		return "", fmt.Errorf("failed to get ActiveConnections property: %v", err)
	}

	if len(activeConnections) == 0 {
		return "", fmt.Errorf("no active connections found")
	}

	for _, activeConnPath := range activeConnections {
		connActive := conn.Object("org.freedesktop.NetworkManager", activeConnPath)

		var dhcpPath dbus.ObjectPath
		err = connActive.Call("org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.NetworkManager.Connection.Active", "Dhcp4Config").Store(&dhcpPath)
		if err != nil {
			log.Println("[INFO] failed to get Dhcp4Config property: ", err)
			continue
		}

		dhcp := conn.Object("org.freedesktop.NetworkManager", dhcpPath)
		var options map[string]dbus.Variant
		err = dhcp.Call("org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.NetworkManager.DHCP4Config", "Options").Store(&options)
		if err != nil {
			log.Println("[INFO] failed to get Options property in DHCP4Config ", dhcpPath, ": ", err)
			continue
		}

		if variant, ok := options["sztp_redirect_urls"]; ok {
			if variant.Signature().String() == "s" {
				sztpRedirectURLs := variant.Value().(string)
				log.Println("[SUCCESS] sztp_redirect_urls: ", sztpRedirectURLs)
				return sztpRedirectURLs, nil
			}
			log.Println("[INFO] sztp_redirect_urls is not a string in DHCP4Config ", dhcpPath)
		} else {
			log.Println("[INFO] sztp_redirect_urls not found in DHCP4Config ", dhcpPath)
		}
	}
	return "", fmt.Errorf("sztp_redirect_urls not found in any active connection")
}
