// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package privnet

import (
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"github.com/cilium/hive/cell"
	"golang.org/x/sys/unix"

	privnetcfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/types"
)

const fibMapName = "cilium_privnet_fib"

// FIBKey is the FIB map key.
type FIBKey struct {
	PrefixLen uint32           `align:"lpm_key"`
	NetID     tables.NetworkID `align:"net_id"`
	Family    uint8            `align:"family"`
	_         [1]uint8         `align:"pad"`
	Address   types.IPv6       `align:"$union0"`
}

const fibKeyStaticPrefixBits = uint32(unsafe.Sizeof(FIBKey{})-
	unsafe.Sizeof(FIBKey{}.PrefixLen)-
	unsafe.Sizeof(FIBKey{}.Address)) * 8

// FIBFlags are the flags in the FIB map value.
type FIBFlags uint8

const (
	// FIBFlagL2Announce is set if the privnet datapath should reply to ARPs/NDs.
	FIBFlagL2Announce FIBFlags = 1 << iota
	// FIBFlagSubnetRoute is set if the address is a subnet route.
	FIBFlagSubnetRoute
	// FIBFlagStaticRoute is set if the address is a static route.
	FIBFlagStaticRoute
)

// FIBVal is the FIB map value.
type FIBVal struct {
	Flags   FIBFlags   `align:"flag_l2_announce"`
	Family  uint8      `align:"family"`
	_       uint16     `align:"pad0"`
	Address types.IPv6 `align:"$union0"`
}

// FIB allows to interact with the private network FIB map.
type FIB struct {
	*bpf.Map
}

func newFIB(
	lc cell.Lifecycle,
	cfg privnetcfg.Config,
	mapCfg Config,
) bpf.MapOut[FIB] {
	fibMap := bpf.NewMap(
		fibMapName,
		ebpf.LPMTrie,
		&FIBKey{},
		&FIBVal{},
		int(mapCfg.MapSize),
		unix.BPF_F_NO_PREALLOC,
	)

	lc.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			if !cfg.Enabled {
				return fibMap.Unpin()
			}
			if err := fibMap.Recreate(); err != nil {
				return fmt.Errorf("failed to create FIB map: %w", err)
			}
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			if !cfg.Enabled {
				return nil
			}
			return fibMap.Close()
		},
	})

	return bpf.NewMapOut(FIB{fibMap})
}

// NewFIBKey constructs a new FIB map key.
func NewFIBKey(netID tables.NetworkID, prefix netip.Prefix) FIBKey {
	family, addr := fromAddr(prefix.Addr())
	prefixLen := fibKeyStaticPrefixBits + uint32(prefix.Bits())

	return FIBKey{
		PrefixLen: prefixLen,
		NetID:     netID,
		Family:    family,
		Address:   addr,
	}
}

func (k FIBKey) String() string {
	return fmt.Sprintf("%#x %s",
		k.NetID,
		k.ToPrefix(),
	)
}

func (k *FIBKey) ToPrefix() netip.Prefix {
	return netip.PrefixFrom(
		toAddr(k.Family, k.Address),
		int(k.PrefixLen)-int(fibKeyStaticPrefixBits),
	)
}

func (*FIBKey) New() bpf.MapKey {
	return &FIBKey{}
}

// NewFIBVal constructs a new FIB map value.
func NewFIBVal(addr netip.Addr, flags FIBFlags) FIBVal {
	family, address := fromAddr(addr)

	return FIBVal{
		Flags:   flags,
		Family:  family,
		Address: address,
	}
}

func (v FIBVal) String() string {
	return fmt.Sprintf("%s %#x",
		v.ToAddr(),
		v.Flags,
	)
}

func (v *FIBVal) ToAddr() netip.Addr {
	return toAddr(v.Family, v.Address)
}

func (*FIBVal) New() bpf.MapValue {
	return &FIBVal{}
}

func fromAddr(ip netip.Addr) (family uint8, res types.IPv6) {
	addr := ip.Unmap()
	family = bpf.EndpointKeyIPv4
	if addr.Is6() {
		family = bpf.EndpointKeyIPv6
	}
	copy(res[:], addr.AsSlice())
	return
}

func toAddr(family uint8, address types.IPv6) netip.Addr {
	var addr netip.Addr

	switch family {
	case bpf.EndpointKeyIPv4:
		addr = netip.AddrFrom4([4]byte(address[:net.IPv4len]))
	case bpf.EndpointKeyIPv6:
		addr = netip.AddrFrom16(address)
	}

	return addr
}
