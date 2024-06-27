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

	var primaryConnPath dbus.ObjectPath
	err = nm.Call("org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.NetworkManager", "PrimaryConnection").Store(&primaryConnPath)
	if err != nil {
		return "", fmt.Errorf("failed to get PrimaryConnection property: %v", err)
	}

	connActive := conn.Object("org.freedesktop.NetworkManager", primaryConnPath)

	var dhcpPath dbus.ObjectPath
	err = connActive.Call("org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.NetworkManager.Connection.Active", "Dhcp4Config").Store(&dhcpPath)
	if err != nil {
		return "", fmt.Errorf("failed to get Dhcp4Config property: %v", err)
	}

	dhcp := conn.Object("org.freedesktop.NetworkManager", dhcpPath)
	var options map[string]dbus.Variant
	err = dhcp.Call("org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.NetworkManager.DHCP4Config", "Options").Store(&options)
	if err != nil {
		return "", fmt.Errorf("failed to get Options property: %v", err)
	}

	if variant, ok := options["sztp_redirect_urls"]; ok {
		if variant.Signature().String() == "s" {
			sztpRedirectURLs := variant.Value().(string)
			log.Println(sztpRedirectURLs)
			return sztpRedirectURLs, nil
		}
		log.Println("sztp_redirect_urls is not a string")
		return "", fmt.Errorf("sztp_redirect_urls is not a string")
	}

	log.Println("sztp_redirect_urls option not found")
	return "", fmt.Errorf("sztp_redirect_urls option not found")
}
