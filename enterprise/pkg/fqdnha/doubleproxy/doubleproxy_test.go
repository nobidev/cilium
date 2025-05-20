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

package doubleproxy

import (
	"net/netip"
	"testing"

	"github.com/cilium/dns"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/daemon/cmd"
	fqdnhaconfig "github.com/cilium/cilium/enterprise/pkg/fqdnha/config"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/tables"
	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/defaultdns"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

// TestDumpRules ensures that Dumprules in enterprise_getallrules.go
// produces correct output.
func TestDumpRules(t *testing.T) {
	log := hivetest.Logger(t)
	localProxy := dnsproxy.NewDNSProxy(log, dnsproxy.DNSProxyConfig{
		Address: "127.0.0.2",
		IPv4:    false,
		IPv6:    false,
	},
		func(ip netip.Addr) (endpoint *endpoint.Endpoint, isHost bool, err error) { return nil, false, nil },
		nil,
		nil,
		func(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, serverAddr netip.AddrPort, msg *dns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
			return nil
		},
	)

	epID := uint64(5)
	portProto := restore.MakeV2PortProto(53, 17)

	cs := mockCachedSelector("selector-string")
	allowExampleCom := policy.L7DataMap{
		cs: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{{
					MatchName: "example.com",
				}},
			},
		},
	}

	expectedConfig := &tables.ProxyConfig{
		ProxyConfigKey: tables.ProxyConfigKey{
			EndpointID: 5,
			PortProto:  portProto,
		},
		SelectorRegexMapping: map[string]string{
			"selector-string": `^(?:example[.]com[.])$`,
		},
		SelectorIdentitiesMapping: map[string][]uint32{
			"selector-string": {1, 2, 3},
		},
	}

	require.Equal(t, expectedConfig, tables.NewProxyConfig(epID, portProto, allowExampleCom))

	_, err := localProxy.UpdateAllowed(epID, portProto, allowExampleCom)
	require.NoError(t, err)

	dump := localProxy.DumpRules()
	require.Len(t, dump, 1)
	require.Equal(t, expectedConfig, tables.NewProxyConfigFromMsg(dump[0]))
}

// TestWriteRules ensures that the statedb table is populated with correct data, both
// on startup and continuing operation.
func TestWriteRules(t *testing.T) {
	log := hivetest.Logger(t)
	localProxy := dnsproxy.NewDNSProxy(log, dnsproxy.DNSProxyConfig{
		Address: "127.0.0.2",
		IPv4:    false,
		IPv6:    false,
	},
		func(ip netip.Addr) (endpoint *endpoint.Endpoint, isHost bool, err error) { return nil, false, nil },
		nil,
		nil,
		func(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, serverAddr netip.AddrPort, msg *dns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
			return nil
		},
	)

	defaultProxy := defaultdns.NewProxy()
	defaultProxy.Set(localProxy)

	cfg := fqdnhaconfig.Config{
		EnableExternalDNSProxy: true,
	}
	db := statedb.New()

	cs := mockCachedSelector("selector-string")
	allowExampleCom := policy.L7DataMap{
		cs: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{{
					MatchName: "example.com",
				}},
			},
		},
	}

	addRule := func(epID uint64, port uint16) {
		t.Helper()
		_, err := defaultProxy.Get().UpdateAllowed(epID, restore.MakeV2PortProto(port, 17), allowExampleCom)
		require.NoError(t, err)
	}

	delRule := func(epID uint64, port uint16) {
		t.Helper()
		_, err := defaultProxy.Get().UpdateAllowed(epID, restore.MakeV2PortProto(port, 17), nil)
		require.NoError(t, err)
	}

	// Add some rules
	addRule(1, 53)
	addRule(2, 53)
	addRule(1, 53)
	addRule(3, 53)
	delRule(3, 53)

	res, fdp := promise.New[*cmd.Daemon]()
	res.Resolve(nil)

	// initialize the doubleproxy
	dp, pcTable, err := NewDoubleProxy(Params{
		Lc:            hivetest.Lifecycle(t),
		DaemonPromise: fdp,
		DefaultProxy:  defaultProxy,
		Cfg:           cfg,
		Log:           hivetest.Logger(t),
		DB:            db,
	})
	require.NoError(t, err)

	require.Equal(t, dp, defaultProxy.Get())

	tableHasRule := func(epid uint16, port uint16) bool {
		t.Helper()
		_, _, found := pcTable.Get(db.ReadTxn(), tables.ConfigByKey(tables.ProxyConfigKey{
			EndpointID: epid,
			PortProto:  restore.MakeV2PortProto(port, 17),
		}))
		return found
	}

	numRules := func() int {
		t.Helper()
		return pcTable.NumObjects(db.ReadTxn())
	}

	// Check that initial load was successful
	require.True(t, tableHasRule(1, 53))
	require.True(t, tableHasRule(2, 53))
	require.Equal(t, 2, numRules())

	// Add 2 rules, count should be 4
	addRule(3, 53)
	addRule(3, 54)
	require.True(t, tableHasRule(3, 53))
	require.True(t, tableHasRule(3, 54))
	require.Equal(t, 4, numRules())

	// Delete 2 rules, one doesn't exist, count should be 3
	delRule(3, 54)
	delRule(3, 55) // doesn't exist
	require.Equal(t, 3, numRules())

	// validate that both existing and newly-added rows are correct

	row, _, found := pcTable.Get(db.ReadTxn(), tables.ConfigByKey(tables.ProxyConfigKey{
		EndpointID: 1,
		PortProto:  restore.MakeV2PortProto(53, 17),
	}))
	require.True(t, found)
	require.Equal(t, &tables.ProxyConfig{
		ProxyConfigKey: tables.ProxyConfigKey{
			EndpointID: 1,
			PortProto:  restore.MakeV2PortProto(53, 17),
		},
		SelectorRegexMapping: map[string]string{
			"selector-string": `^(?:example[.]com[.])$`,
		},
		SelectorIdentitiesMapping: map[string][]uint32{
			"selector-string": {1, 2, 3},
		},
	},
		row)

	row, _, found = pcTable.Get(db.ReadTxn(), tables.ConfigByKey(tables.ProxyConfigKey{
		EndpointID: 3,
		PortProto:  restore.MakeV2PortProto(53, 17),
	}))
	require.True(t, found)
	require.Equal(t, &tables.ProxyConfig{
		ProxyConfigKey: tables.ProxyConfigKey{
			EndpointID: 3,
			PortProto:  restore.MakeV2PortProto(53, 17),
		},
		SelectorRegexMapping: map[string]string{
			"selector-string": `^(?:example[.]com[.])$`,
		},
		SelectorIdentitiesMapping: map[string][]uint32{
			"selector-string": {1, 2, 3},
		},
	},
		row)
}

type mockCachedSelector string

func (m mockCachedSelector) GetSelections(v *versioned.VersionHandle) identity.NumericIdentitySlice {
	return []identity.NumericIdentity{1, 2, 3}
}
func (m mockCachedSelector) GetMetadataLabels() labels.LabelArray { panic("not impl") }
func (m mockCachedSelector) Selects(v *versioned.VersionHandle, _ identity.NumericIdentity) bool {
	panic("not impl")
}
func (m mockCachedSelector) IsWildcard() bool { panic("not impl") }
func (m mockCachedSelector) IsNone() bool     { panic("not impl") }
func (m mockCachedSelector) String() string   { return string(m) }
