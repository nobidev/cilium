//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package tables

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	fqdnpb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/config"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/u8proto"
)

type ProxyConfigKey struct {
	EndpointID uint16
	PortProto  restore.PortProto
}

type ProxyConfig struct {
	ProxyConfigKey

	SelectorRegexMapping      map[string]string
	SelectorIdentitiesMapping map[string][]uint32
}

func NewProxyConfigTable(cfg config.Config, db *statedb.DB) (statedb.RWTable[*ProxyConfig], statedb.Table[*ProxyConfig], error) {
	if !cfg.EnableExternalDNSProxy {
		return nil, nil, nil
	}
	tbl, err := statedb.NewTable(
		db,
		ProxyConfigTableName,
		epPortIndex,
	)
	return tbl, tbl, err
}

var (
	epPortIndex = statedb.Index[*ProxyConfig, ProxyConfigKey]{
		Name: "ID",
		FromObject: func(obj *ProxyConfig) index.KeySet {
			return index.NewKeySet(obj.asKey())
		},
		FromKey: func(k ProxyConfigKey) index.Key { return k.asKey() },
		FromString: func(key string) (index.Key, error) {
			var out index.Key
			parts := strings.Split(key, ":")
			n := len(parts)
			if n == 0 {
				return index.Key{}, fmt.Errorf(`bad key, expected "<epid>:<proto>:<port>", e.g. "1234:udp:53"`)
			}
			if n >= 1 {
				epid, err := strconv.Atoi(parts[0])
				if err != nil || epid > math.MaxUint16 || epid <= 0 {
					return index.Key{}, fmt.Errorf("invalid epid %s: %w", parts[0], err)
				}
				out = binary.NativeEndian.AppendUint16(out, uint16(epid))
			}
			if n >= 2 {
				protoNum, err := u8proto.ParseProtocol(parts[1])
				if err != nil {
					return index.Key{}, err
				}
				out = append(out, byte(protoNum))
			}
			if n == 3 {
				port, err := strconv.Atoi(parts[0])
				if err != nil || port > math.MaxUint16 || port <= 0 {
					return index.Key{}, fmt.Errorf("invalid epid %s: %w", parts[0], err)
				}
				out = binary.NativeEndian.AppendUint16(out, uint16(port))
			}
			return out, nil
		},
		Unique: true,
	}

	ConfigByKey = epPortIndex.Query
)

const (
	ProxyConfigTableName = "enterprise-fqdnha-proxyconfig"
)

func (pck *ProxyConfigKey) asKey() index.Key {
	key := make(index.Key, 0, 5)
	key = binary.NativeEndian.AppendUint16(key, pck.EndpointID)
	key = append(key, pck.PortProto.Protocol())
	key = binary.NativeEndian.AppendUint16(key, pck.PortProto.Port())
	return key
}

// NewProxyConfig converts a policy l7 config to a ProxyConfig table row.
func NewProxyConfig(endpointID uint64, destPortProto restore.PortProto, newRules policy.L7DataMap) *ProxyConfig {
	pc := &ProxyConfig{
		ProxyConfigKey: ProxyConfigKey{
			// only ever u16
			EndpointID: uint16(endpointID),
			PortProto:  destPortProto,
		},
		SelectorRegexMapping:      make(map[string]string, len(newRules)),
		SelectorIdentitiesMapping: make(map[string][]uint32, len(newRules)),
	}

	for selector, l7rules := range newRules {
		pc.SelectorRegexMapping[selector.String()] = dnsproxy.GeneratePattern(l7rules)
		// returned nids are not "transactional", i.e., a concurrently added identity may be missing from
		// the selections of one selector, but appear on the selections of another
		nids := selector.GetSelections().AsUint32Slice()
		pc.SelectorIdentitiesMapping[selector.String()] = nids
	}

	return pc
}

// ToMsg converts a ProxyConfig to a gRPC FQDNRules message.
func (pc *ProxyConfig) ToMsg(deleted bool) *fqdnpb.FQDNRules {
	out := &fqdnpb.FQDNRules{
		EndpointID: uint64(pc.EndpointID),
		DestPort:   uint32(pc.PortProto.Port()),
		DestProto:  uint32(pc.PortProto.Protocol()),
		Rules:      &fqdnpb.L7Rules{},
	}
	if deleted {
		return out
	}

	out.Rules.SelectorRegexMapping = pc.SelectorRegexMapping
	out.Rules.SelectorIdentitiesMapping = make(map[string]*fqdnpb.IdentityList, len(pc.SelectorIdentitiesMapping))
	for k, v := range pc.SelectorIdentitiesMapping {
		out.Rules.SelectorIdentitiesMapping[k] = &fqdnpb.IdentityList{List: v}
	}

	return out
}

func (pc *ProxyConfig) TableHeader() []string {
	return []string{
		"EndpointID",
		"Proto",
		"Port",
		"SelectorRegexMapping",
		"SelectorIdentitiesMapping",
	}
}

func (pc *ProxyConfig) TableRow() []string {
	return []string{
		fmt.Sprint(pc.EndpointID),
		u8proto.U8proto(pc.PortProto.Protocol()).String(),
		fmt.Sprint(pc.PortProto.Port()),
		fmt.Sprint(pc.SelectorRegexMapping),
		fmt.Sprint(pc.SelectorIdentitiesMapping),
	}
}
