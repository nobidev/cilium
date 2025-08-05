//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package extepspolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"unsafe"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
)

const (
	// MapName is the name of the external endpoints policy map.
	MapName = "cilium_ext_eps_policy"
)

// Key is the key for the external endpoints policy map.
type Key struct{ bpf.EndpointKey }

func (k *Key) New() bpf.MapKey { return &Key{} }
func (k *Key) String() string  { return k.EndpointKey.String() }

// Value is the value for the external endpoints policy map.
type Value struct {
	// Fd is the file descriptor of the inner policy map
	Fd uint32
}

func (v *Value) New() bpf.MapValue { return &Value{} }
func (v *Value) String() string    { return fmt.Sprintf("fd=%d", v.Fd) }

type extEpsPolMap struct {
	m       *bpf.Map
	enabled enabled
}

func newMap(lc cell.Lifecycle, cfg Config, pc policymap.PolicyConfig, en enabled) (bpf.MapOut[*extEpsPolMap], defines.NodeOut) {
	innerMapSpec := &ebpf.MapSpec{
		Type:      ebpf.LPMTrie,
		KeySize:   uint32(unsafe.Sizeof(policymap.PolicyKey{})),
		ValueSize: uint32(unsafe.Sizeof(policymap.PolicyEntry{})),
		// Mimic the same logic in [policymap.createFactory].
		MaxEntries: uint32(max(min(pc.BpfPolicyMapMax, option.PolicyMapMax), option.PolicyMapMin)),
	}

	extEPsMap := bpf.NewMapWithInnerSpec(
		MapName,
		ebpf.HashOfMaps,
		&Key{},
		&Value{},
		int(cfg.ExtEpsPolicyMapMax),
		0,
		innerMapSpec,
	)

	out := &extEpsPolMap{m: extEPsMap, enabled: en}
	lc.Append(out)

	return bpf.NewMapOut(out), defines.NodeOut{
		NodeDefines: defines.Map{
			"EXT_EPS_POLICY_MAP_SIZE": strconv.FormatUint(uint64(cfg.ExtEpsPolicyMapMax), 10),
		},
	}
}

func (m *extEpsPolMap) Start(cell.HookContext) error {
	if !m.enabled {
		if err := m.m.Unpin(); err != nil {
			return fmt.Errorf("failed to unpin external endpoints policy map: %w", err)
		}
		return nil
	}

	if err := m.m.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to create external endpoints policy map: %w", err)
	}

	return nil
}

func (m *extEpsPolMap) Stop(cell.HookContext) error {
	if m.enabled {
		m.m.Close()
	}

	return nil
}

func (m *extEpsPolMap) Upsert(ip netip.Addr, pm *policymap.PolicyMap) error {
	var (
		key Key
		val Value
	)

	if !ip.IsValid() {
		return errors.New("invalid ip address")
	}

	if pm == nil || pm.FD() < 0 {
		return errors.New("invalid policy map")
	}

	key.EndpointKey = bpf.NewEndpointKey(ip.AsSlice(), 0)
	val.Fd = uint32(pm.FD())
	return m.m.Update(&key, &val)
}

func (m *extEpsPolMap) Delete(ip netip.Addr) error {
	var key Key

	if !ip.IsValid() {
		return errors.New("invalid ip address")
	}

	key.EndpointKey = bpf.NewEndpointKey(ip.AsSlice(), 0)
	return m.m.Delete(&key)
}
