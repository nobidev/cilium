//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lbflowlogs

import (
	"net"
	"testing"
)

func TestInterfaceByIndexCaches(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("failed to list interfaces: %v", err)
	}
	if len(interfaces) == 0 {
		t.Skip("no network interfaces available")
	}

	orig := ifaces
	ifaces = map[int]string{}
	defer func() {
		ifaces = orig
	}()

	iface := interfaces[0]
	name, err := InterfaceByIndex(iface.Index)
	if err != nil {
		t.Fatalf("InterfaceByIndex returned error: %v", err)
	}
	if name != iface.Name {
		t.Fatalf("expected interface name %q, got %q", iface.Name, name)
	}

	ifaces[iface.Index] = "cached"
	cached, err := InterfaceByIndex(iface.Index)
	if err != nil {
		t.Fatalf("InterfaceByIndex returned error: %v", err)
	}
	if cached != "cached" {
		t.Fatalf("expected cached name, got %q", cached)
	}
}
