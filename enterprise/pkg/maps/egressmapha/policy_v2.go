//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressmapha

import (
	"fmt"
	"iter"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	PolicyMapNameV2 = "cilium_egress_gw_ha_policy_v4_v2"
)

// EgressPolicyKey4 is the key of an egress policy map.
type EgressPolicyV2Key4 struct {
	// PrefixLen is full 32 bits of SourceIP + DestCIDR's mask bits
	PrefixLen uint32 `align:"lpm_key"`

	SourceIP types.IPv4 `align:"saddr"`
	DestCIDR types.IPv4 `align:"daddr"`
}

// EgressPolicyVal4 is the value of an egress policy map.
type EgressPolicyV2Val4 struct {
	Size          uint32                      `align:"size"`
	EgressIP      types.IPv4                  `align:"egress_ip"`
	GatewayIPs    [maxGatewayNodes]types.IPv4 `align:"gateway_ips"`
	EgressIfindex uint32                      `align:"egress_ifindex"`
}

// PolicyMap is used to communicate EGW policies to the datapath.
type PolicyMapV2 interface {
	Lookup(sourceIP netip.Addr, destCIDR netip.Prefix) (*EgressPolicyV2Val4, error)
	Update(sourceIP netip.Addr, destCIDR netip.Prefix, egressIP netip.Addr, gatewayIPs []netip.Addr, egressIfindex uint32) error
	Delete(sourceIP netip.Addr, destCIDR netip.Prefix) error
	IterateWithCallback(EgressPolicyV2IterateCallback) error
}

// policyMapV2 is the internal representation of an egress policy map.
type policyMapV2 struct {
	m *bpf.Map
}

func createPolicyMapV2FromDaemonConfig(in struct {
	cell.In

	Lifecycle cell.Lifecycle
	*option.DaemonConfig
	PolicyConfig
	MetricsRegistry *metrics.Registry
}) (out struct {
	cell.Out

	bpf.MapOut[PolicyMapV2]
	defines.NodeOut
}) {
	out.NodeDefines = map[string]string{
		"EGRESS_GW_HA_POLICY_MAP_V2_SIZE": fmt.Sprint(in.EgressGatewayHAPolicyMapMax),
	}

	if !in.EnableIPv4EgressGatewayHA {
		return
	}

	out.MapOut = bpf.NewMapOut(PolicyMapV2(createPolicyMapV2(in.Lifecycle, in.MetricsRegistry, in.PolicyConfig, ebpf.PinByName)))
	return
}

// CreatePrivatePolicyMap creates an unpinned policy map.
//
// Useful for testing.
func CreatePrivatePolicyMapV2(lc cell.Lifecycle, registry *metrics.Registry, cfg PolicyConfig) PolicyMapV2 {
	return createPolicyMapV2(lc, registry, cfg, ebpf.PinNone)
}

func createPolicyMapV2(lc cell.Lifecycle, registry *metrics.Registry, cfg PolicyConfig, pinning ebpf.PinType) *policyMapV2 {
	m := bpf.NewMap(
		PolicyMapNameV2,
		ebpf.LPMTrie,
		&EgressPolicyV2Key4{},
		&EgressPolicyV2Val4{},
		cfg.EgressGatewayHAPolicyMapMax,
		0,
	).WithPressureMetric(registry)

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			switch pinning {
			case ebpf.PinNone:
				return m.CreateUnpinned()
			case ebpf.PinByName:
				return m.OpenOrCreate()
			}
			return fmt.Errorf("received unexpected pin type: %d", pinning)
		},
		OnStop: func(cell.HookContext) error {
			return m.Close()
		},
	})

	return &policyMapV2{m}
}

func OpenPinnedPolicyMapV2(log *slog.Logger) (PolicyMapV2, error) {
	m, err := bpf.OpenMap(bpf.MapPath(log, PolicyMapNameV2), &EgressPolicyV2Key4{}, &EgressPolicyV2Val4{})
	if err != nil {
		return nil, err
	}

	return &policyMapV2{m}, nil
}

// NewEgressPolicyKey4 returns a new EgressPolicyKey4 object representing the
// (source IP, destination CIDR) tuple.
func NewEgressPolicyV2Key4(sourceIP netip.Addr, destPrefix netip.Prefix) EgressPolicyV2Key4 {
	key := EgressPolicyV2Key4{}
	ones := destPrefix.Bits()
	key.SourceIP.FromAddr(sourceIP)
	key.DestCIDR.FromAddr(destPrefix.Addr())
	key.PrefixLen = PolicyStaticPrefixBits + uint32(ones)
	return key
}

// NewEgressPolicyVal4 returns a new EgressPolicyVal4 object representing for
// the given egress IP and gateway IPs
func NewEgressPolicyV2Val4(egressIP netip.Addr, gatewayIPs []netip.Addr, egressIfindex uint32) EgressPolicyV2Val4 {
	val := EgressPolicyV2Val4{
		Size:          uint32(len(gatewayIPs)),
		EgressIfindex: egressIfindex,
	}

	val.EgressIP.FromAddr(egressIP)
	for i, gw := range gatewayIPs {
		val.GatewayIPs[i].FromAddr(gw)
	}

	return val
}

// String returns the string representation of an egress policy key.
func (k *EgressPolicyV2Key4) String() string {
	return fmt.Sprintf("%s %s/%d", k.SourceIP, k.DestCIDR, k.destCIDRBits())
}

// New returns an egress policy key
func (k *EgressPolicyV2Key4) New() bpf.MapKey { return &EgressPolicyV2Key4{} }

// Match returns true if the sourceIP and destCIDR parameters match the egress
// policy key.
func (k *EgressPolicyV2Key4) Match(sourceIP netip.Addr, destCIDR netip.Prefix) bool {
	return k.GetSourceIP() == sourceIP &&
		k.GetDestCIDR() == destCIDR
}

// GetSourceIP returns the egress policy key's source IP.
func (k *EgressPolicyV2Key4) GetSourceIP() netip.Addr {
	addr, _ := netipx.FromStdIP(k.SourceIP.IP())
	return addr
}

// GetDestCIDR returns the egress policy key's destination CIDR.
func (k *EgressPolicyV2Key4) GetDestCIDR() netip.Prefix {
	addr, _ := netipx.FromStdIP(k.DestCIDR.IP())
	return netip.PrefixFrom(addr, int(k.destCIDRBits()))
}

func (k *EgressPolicyV2Key4) destCIDRBits() uint32 {
	return max(k.PrefixLen, PolicyStaticPrefixBits) - PolicyStaticPrefixBits
}

// New returns an egress policy value
func (v *EgressPolicyV2Val4) New() bpf.MapValue { return &EgressPolicyV2Val4{} }

// Match returns true if the egressIP and gatewayIPs parameters match the egress
// policy value.
func (v *EgressPolicyV2Val4) Match(egressIP netip.Addr, gatewayIPs []netip.Addr, egressIfindex uint32) bool {
	if v.GetEgressIP() != egressIP {
		return false
	}

	if v.EgressIfindex != egressIfindex {
		return false
	}

	if v.Size != uint32(len(gatewayIPs)) {
		return false
	}

	for i := 0; i < len(gatewayIPs); i++ {
		if v.GatewayIPs[i].Addr() != gatewayIPs[i] {
			return false
		}
	}

	return true
}

// GetEgressIP returns the egress policy value's egress IP.
func (v *EgressPolicyV2Val4) GetEgressIP() netip.Addr {
	return v.EgressIP.Addr()
}

// GetGatewayIPs returns the egress policy value's gateway IP.
func (v *EgressPolicyV2Val4) GetGatewayIPs() iter.Seq[netip.Addr] {
	return func(yield func(netip.Addr) bool) {
		for i := uint32(0); i < v.Size; i++ {
			if !yield(v.GatewayIPs[i].Addr()) {
				return
			}
		}
	}
}

// String returns the string representation of an egress policy value.
func (v *EgressPolicyV2Val4) String() string {
	return fmt.Sprintf("%v %s %d", slices.Collect(v.GetGatewayIPs()), v.GetEgressIP(), v.EgressIfindex)
}

// Lookup returns the egress policy object associated with the provided (source
// IP, destination CIDR) tuple.
func (m *policyMapV2) Lookup(sourceIP netip.Addr, destCIDR netip.Prefix) (*EgressPolicyV2Val4, error) {
	key := NewEgressPolicyV2Key4(sourceIP, destCIDR)
	val, err := m.m.Lookup(&key)
	if err != nil {
		return nil, err
	}

	return val.(*EgressPolicyV2Val4), err
}

// Update updates the (sourceIP, destCIDR) egress policy entry with the provided
// egress and gateway IPs.
func (m *policyMapV2) Update(sourceIP netip.Addr, destCIDR netip.Prefix, egressIP netip.Addr, gatewayIPs []netip.Addr, egressIfindex uint32) error {
	key := NewEgressPolicyV2Key4(sourceIP, destCIDR)
	val := NewEgressPolicyV2Val4(egressIP, gatewayIPs, egressIfindex)

	return m.m.Update(&key, &val)
}

// Delete deletes the (sourceIP, destCIDR) egress policy entry.
func (m *policyMapV2) Delete(sourceIP netip.Addr, destCIDR netip.Prefix) error {
	key := NewEgressPolicyV2Key4(sourceIP, destCIDR)

	return m.m.Delete(&key)
}

// EgressPolicyIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an egress policy map.
type EgressPolicyV2IterateCallback func(*EgressPolicyV2Key4, *EgressPolicyV2Val4)

// IterateWithCallback iterates through all the keys/values of an egress policy
// map, passing each key/value pair to the cb callback.
func (m policyMapV2) IterateWithCallback(cb EgressPolicyV2IterateCallback) error {
	return m.m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*EgressPolicyV2Key4)
		value := v.(*EgressPolicyV2Val4)

		cb(key, value)
	})
}
