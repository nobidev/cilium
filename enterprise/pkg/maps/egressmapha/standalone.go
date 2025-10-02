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
	"log/slog"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/types"
)

const (
	SEGWMapName    = "cilium_egress_gw_standalone_v4"
	MaxSEGWEntries = 1 << 14
)

// SEGWMapKey4 is the key of a SEGW map.
type SEGWMapKey4 struct {
	EndpointIP types.IPv4 `align:"endpoint_ip"`
}

// SEGWMapVal4 is the value of a SEGW map.
type SEGWMapVal4 struct {
	SecurityIdentity uint32     `align:"sec_identity"`
	TunnelEndpoint   types.IPv4 `align:"tunnel_endpoint"`
}

func (k *SEGWMapKey4) New() bpf.MapKey   { return &SEGWMapKey4{} }
func (k *SEGWMapKey4) String() string    { return k.EndpointIP.String() }
func (v *SEGWMapVal4) New() bpf.MapValue { return &SEGWMapVal4{} }
func (v *SEGWMapVal4) String() string {
	return fmt.Sprintf("identity=%d, tunnelendpoint=%s", v.SecurityIdentity, v.TunnelEndpoint)
}

type SEGWMapConfig struct {
	// StandaloneEgressGatewayMapMax is the maximum number of entries
	// allowed in the BPF SEGW map.
	StandaloneEgressGatewayMapMax int
}

var DefaultSEGWMapConfig = SEGWMapConfig{
	StandaloneEgressGatewayMapMax: 1 << 14,
}

func (def SEGWMapConfig) Flags(flags *pflag.FlagSet) {
	flags.Int("standalone-egress-gateway-map-max", def.StandaloneEgressGatewayMapMax, "Maximum number of entries in the standalone egress gateway map")
}

// SEGWMap is used to store endpoint IP to tunnel endpoint mappings for the standalone egress gateway.
type SEGWMap interface {
	IterateWithCallback(SEGWMapIterateCallback) error
}

// segwMap is the internal representation of a standalone egress gateway map.
type segwMap struct {
	m *bpf.Map
}

func segwMapDefines(cfg SEGWMapConfig) defines.NodeOut {
	return defines.NodeOut{
		NodeDefines: map[string]string{
			"EGRESS_GW_STANDALONE_MAP_SIZE": fmt.Sprint(cfg.StandaloneEgressGatewayMapMax),
		},
	}
}

func OpenPinnedSEGWMap(log *slog.Logger) (SEGWMap, error) {
	m, err := bpf.OpenMap(bpf.MapPath(log, SEGWMapName), &SEGWMapKey4{}, &SEGWMapVal4{})
	if err != nil {
		return nil, err
	}

	return &segwMap{m}, nil
}

// SEGWMapIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of a standalone egress gateway map.
type SEGWMapIterateCallback func(*SEGWMapKey4, *SEGWMapVal4)

// IterateWithCallback iterates through all the keys/values of a standalone
// egress gateway map, passing each key/value pair to the cb callback.
func (m segwMap) IterateWithCallback(cb SEGWMapIterateCallback) error {
	return m.m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*SEGWMapKey4)
		value := v.(*SEGWMapVal4)

		cb(key, value)
	})
}
