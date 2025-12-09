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

const pipMapName = "cilium_privnet_pip"

// PIPKey is the PIP map key.
type PIPKey struct {
	PrefixLen uint32     `align:"lpm_key"`
	Family    uint8      `align:"family"`
	_         [3]uint8   `align:"pad"`
	Address   types.IPv6 `align:"$union0"`
}

const pipKeyStaticPrefixBits = uint32(unsafe.Sizeof(PIPKey{})-
	unsafe.Sizeof(PIPKey{}.PrefixLen)-
	unsafe.Sizeof(PIPKey{}.Address)) * 8

// PIPFlags are the flags in the PIP map value.
type PIPFlags uint8

// PIPVal is the PIP map value.
type PIPVal struct {
	MAC     types.MACAddr `align:"mac"`
	_       uint16
	Address types.IPv6       `align:"$union0"`
	Flags   PIPFlags         `align:"flags"`
	Family  uint8            `align:"family"`
	NetID   tables.NetworkID `align:"net_id"`
	IfIndex uint32           `align:"ifindex"`
}

// PIP allows to interact with the private network PIP map.
type PIP struct {
	*bpf.Map
}

func newPIP(
	lc cell.Lifecycle,
	cfg privnetcfg.Config,
	mapCfg Config,
) bpf.MapOut[PIP] {
	pipMap := bpf.NewMap(
		pipMapName,
		ebpf.LPMTrie,
		&PIPKey{},
		&PIPVal{},
		int(mapCfg.MapSize),
		unix.BPF_F_NO_PREALLOC,
	)

	lc.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			if !cfg.Enabled {
				return pipMap.Unpin()
			}
			if err := pipMap.Recreate(); err != nil {
				return fmt.Errorf("failed to create PIP map: %w", err)
			}
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			if !cfg.Enabled {
				return nil
			}
			return pipMap.Close()
		},
	})

	return bpf.NewMapOut(PIP{pipMap})
}

// NewPIPKey constructs a new PIP map key.
func NewPIPKey(prefix netip.Prefix) PIPKey {
	family, addr := fromAddr(prefix.Addr())
	prefixLen := pipKeyStaticPrefixBits + uint32(prefix.Bits())

	return PIPKey{
		PrefixLen: prefixLen,
		Family:    family,
		Address:   addr,
	}
}

func (k PIPKey) String() string {
	return k.ToPrefix().String()
}

func (k *PIPKey) ToPrefix() netip.Prefix {
	return netip.PrefixFrom(
		toAddr(k.Family, k.Address),
		int(k.PrefixLen)-int(pipKeyStaticPrefixBits),
	)
}

func (*PIPKey) New() bpf.MapKey {
	return &PIPKey{}
}

func NewPIPVal(
	netID tables.NetworkID,
	addr netip.Addr,
	mac types.MACAddr,
	ifindex uint32,
) PIPVal {
	family, address := fromAddr(addr)

	return PIPVal{
		Family:  family,
		Address: address,
		MAC:     mac,
		NetID:   netID,
		IfIndex: ifindex,
	}
}

func (v PIPVal) String() string {
	return fmt.Sprintf("%#x %s %d %s %#x",
		v.NetID,
		v.ToAddr(),
		v.IfIndex,
		v.MAC,
		v.Flags,
	)
}

func (v *PIPVal) ToAddr() netip.Addr {
	return toAddr(v.Family, v.Address)
}

func (*PIPVal) New() bpf.MapValue {
	return &PIPVal{}
}
