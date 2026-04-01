// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"
)

type BPFFSPaths struct {
	CiliumPath    string
	TCGlobalsPath string
	StateDir      string
}

// devicesDir returns the path to the 'devices' directory on bpffs, usually
// /sys/fs/bpf/cilium/devices. It does not ensure the directory exists.
func (p *BPFFSPaths) devicesDir() string {
	return filepath.Join(p.CiliumPath, "devices")
}

// DeviceDir returns the path to the per-device directory on bpffs, usually
// /sys/fs/bpf/cilium/devices/<device>. It does not ensure the directory exists.
func (p *BPFFSPaths) DeviceDir(device netlink.Link) string {
	// If a device name contains a "." we must sanitize the string to satisfy bpffs directory path
	// requirements. The string of a directory path on bpffs is not allowed to contain any "." characters.
	// By replacing "." with "-", we circurmvent this limitation. This also introduces a small
	// risk of naming collisions, e.g "eth-0" and "eth.0" would translate to the same bpffs directory.
	// The probability of this happening in practice should be very small.
	return filepath.Join(p.devicesDir(), strings.ReplaceAll(device.Attrs().Name, ".", "-"))
}

// DeviceLinksDir returns the bpffs path to the per-device links directory,
// usually /sys/fs/bpf/cilium/devices/<device>/links. It does not ensure the
// directory exists.
func (p *BPFFSPaths) DeviceLinksDir(device netlink.Link) string {
	return filepath.Join(p.DeviceDir(device), "links")
}

// endpointsDir returns the path to the 'endpoints' directory on bpffs, usually
// /sys/fs/bpf/cilium/endpoints. It does not ensure the directory exists.
func (p *BPFFSPaths) endpointsDir() string {
	return filepath.Join(p.CiliumPath, "endpoints")
}

// EndpointDir returns the path to the per-endpoint directory on bpffs,
// usually /sys/fs/bpf/cilium/endpoints/<endpoint-id>. It does not ensure the
// directory exists.
func (p *BPFFSPaths) EndpointDir(ep Endpoint) string {
	return filepath.Join(p.endpointsDir(), ep.StringID())
}

// EndpointLinksDir returns the bpffs path to the per-endpoint links directory,
// usually /sys/fs/bpf/cilium/endpoints/<endpoint-id>/links. It does not ensure the
// directory exists.
func (p *BPFFSPaths) EndpointLinksDir(ep Endpoint) string {
	return filepath.Join(p.EndpointDir(ep), "links")
}

// StateDeviceDir returns the path to the per-device directory in the Cilium
// state directory, usually /var/run/cilium/bpf/<device>. It does not ensure the
// directory exists.
func (p *BPFFSPaths) StateDeviceDir(device string) string {
	if device == "" {
		return ""
	}
	return filepath.Join(p.StateDir, "bpf", device)
}
