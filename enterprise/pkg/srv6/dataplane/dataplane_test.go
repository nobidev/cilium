//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/rib"
	srv6Types "github.com/cilium/cilium/enterprise/pkg/srv6/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/maps/srv6map"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/types"
)

type mockPolicyMap struct {
	data map[srv6map.PolicyKey]types.IPv6
}

func newMockPolicyMap() *mockPolicyMap {
	return &mockPolicyMap{
		data: make(map[srv6map.PolicyKey]types.IPv6),
	}
}

func (m *mockPolicyMap) Update(k *srv6map.PolicyKey, v types.IPv6) error {
	m.data[*k] = v
	return nil
}

func (m *mockPolicyMap) Delete(k *srv6map.PolicyKey) error {
	delete(m.data, *k)
	return nil
}

func (m *mockPolicyMap) IterateWithCallback(cb srv6map.SRv6PolicyIterateCallback) error {
	for k, v := range m.data {
		cb(&k, &srv6map.PolicyValue{SID: v})
	}
	return nil
}

type mockSIDMap struct {
	data map[srv6map.SIDKey]uint32
}

func newMockSidMap() *mockSIDMap {
	return &mockSIDMap{
		data: make(map[srv6map.SIDKey]uint32),
	}
}

func (m *mockSIDMap) Update(k *srv6map.SIDKey, vrfID uint32) error {
	if k == nil {
		return errors.New("SID key cannot be nil")
	}
	m.data[*k] = vrfID
	return nil
}

func (m *mockSIDMap) Delete(k *srv6map.SIDKey) error {
	if k == nil {
		return errors.New("SID key cannot be nil")
	}
	delete(m.data, *k)
	return nil
}

func (m *mockSIDMap) IterateWithCallback(cb srv6map.SRv6SIDIterateCallback) error {
	for k, v := range m.data {
		cb(&k, &srv6map.SIDValue{VRFID: v})
	}
	return nil
}

func realSRv6Maps(t *testing.T) (policyMap, policyMap, sidMap) {
	var (
		policyMap4 *srv6map.PolicyMap4
		policyMap6 *srv6map.PolicyMap6
		sidMap     *srv6map.SIDMap
	)

	t.Helper()

	hive := hive.New(
		srv6map.Cell,
		cell.Provide(func() *option.DaemonConfig {
			return &option.DaemonConfig{
				EnableSRv6: true,
			}
		}),
		cell.Invoke(func(pm4 *srv6map.PolicyMap4, pm6 *srv6map.PolicyMap6, sm *srv6map.SIDMap) {
			policyMap4 = pm4
			policyMap6 = pm6
			sidMap = sm

			t.Cleanup(func() {
				policyMap4.Unpin()
				policyMap6.Unpin()
				sidMap.Unpin()
			})
		}),
	)

	hive.Start(hivetest.Logger(t), context.TODO())

	t.Cleanup(func() {
		hive.Stop(hivetest.Logger(t), context.TODO())
	})

	return policyMap4, policyMap6, sidMap
}

func TestDataPlane_HEncaps(t *testing.T) {
	sid0 := netip.MustParseAddr("2001:db8::1")
	sid1 := netip.MustParseAddr("2001:db8::2")

	hEncapsRoute0 := &rib.Route{
		Prefix: netip.MustParsePrefix("10.0.0.0/24"),
		NextHop: &rib.HEncaps{
			Segments: []srv6Types.SID{
				srv6Types.MustNewSID(sid0),
			},
		},
	}

	hEncapsRoute1 := &rib.Route{
		Prefix: netip.MustParsePrefix("10.0.0.0/24"),
		NextHop: &rib.HEncaps{
			Segments: []srv6Types.SID{
				srv6Types.MustNewSID(sid1),
			},
		},
	}

	invalidHEncapsRoute0 := &rib.Route{
		// IPv6 prefix is not supported
		Prefix: netip.MustParsePrefix("fd00:1234::/64"),
		NextHop: &rib.HEncaps{
			Segments: []srv6Types.SID{
				srv6Types.MustNewSID(sid1),
			},
		},
	}

	invalidHEncapsRoute1 := &rib.Route{
		Prefix: netip.MustParsePrefix("10.0.0.0/24"),
		NextHop: &rib.HEncaps{
			// Empty segments are not supported
			Segments: []srv6Types.SID{},
		},
	}

	invalidHEncapsRoute2 := &rib.Route{
		Prefix: netip.MustParsePrefix("10.0.0.0/24"),
		NextHop: &rib.HEncaps{
			// Multiple segments are not supported
			Segments: []srv6Types.SID{
				srv6Types.MustNewSID(sid0),
				srv6Types.MustNewSID(sid1),
			},
		},
	}

	tests := []struct {
		name               string
		updates            []*rib.RIBUpdate
		expectedPolicyMap4 map[srv6map.PolicyKey]types.IPv6
	}{
		{
			name: "New Route",
			updates: []*rib.RIBUpdate{
				{
					VRFID:   1,
					NewBest: hEncapsRoute0,
				},
			},
			expectedPolicyMap4: map[srv6map.PolicyKey]types.IPv6{
				{
					VRFID:    1,
					DestCIDR: netip.MustParsePrefix("10.0.0.0/24"),
				}: types.IPv6(sid0.As16()),
			},
		},
		{
			name: "Two Routes",
			updates: []*rib.RIBUpdate{
				{
					VRFID:   1,
					NewBest: hEncapsRoute0,
				},
				{
					VRFID:   2,
					NewBest: hEncapsRoute1,
				},
			},
			expectedPolicyMap4: map[srv6map.PolicyKey]types.IPv6{
				{
					VRFID:    1,
					DestCIDR: netip.MustParsePrefix("10.0.0.0/24"),
				}: types.IPv6(sid0.As16()),
				{
					VRFID:    2,
					DestCIDR: netip.MustParsePrefix("10.0.0.0/24"),
				}: types.IPv6(sid1.As16()),
			},
		},
		{
			name: "Update Route",
			updates: []*rib.RIBUpdate{
				{
					VRFID:   1,
					NewBest: hEncapsRoute0,
				},
				{
					VRFID:   1,
					OldBest: hEncapsRoute0,
					NewBest: hEncapsRoute1,
				},
			},
			expectedPolicyMap4: map[srv6map.PolicyKey]types.IPv6{
				{
					VRFID:    1,
					DestCIDR: netip.MustParsePrefix("10.0.0.0/24"),
				}: types.IPv6(sid1.As16()),
			},
		},
		{
			name: "New Route to Invalid VRF",
			updates: []*rib.RIBUpdate{
				{
					VRFID:   0,
					NewBest: hEncapsRoute0,
				},
			},
			expectedPolicyMap4: map[srv6map.PolicyKey]types.IPv6{},
		},
		{
			name: "New Invalid IPv6 Route",
			updates: []*rib.RIBUpdate{
				{
					VRFID:   1,
					NewBest: invalidHEncapsRoute0,
				},
			},
			expectedPolicyMap4: map[srv6map.PolicyKey]types.IPv6{},
		},
		{
			name: "New Invalid Empty Segment Route",
			updates: []*rib.RIBUpdate{
				{
					VRFID:   1,
					NewBest: invalidHEncapsRoute1,
				},
			},
			expectedPolicyMap4: map[srv6map.PolicyKey]types.IPv6{},
		},
		{
			name: "New Invalid Multi Segment Route",
			updates: []*rib.RIBUpdate{
				{
					VRFID:   1,
					NewBest: invalidHEncapsRoute2,
				},
			},
			expectedPolicyMap4: map[srv6map.PolicyKey]types.IPv6{},
		},
		{
			name: "Delete Route",
			updates: []*rib.RIBUpdate{
				{
					VRFID:   1,
					NewBest: hEncapsRoute0,
				},
				{
					VRFID:   1,
					OldBest: hEncapsRoute0,
				},
			},
			expectedPolicyMap4: map[srv6map.PolicyKey]types.IPv6{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var policyMap4 policyMap
			if !testutils.IsPrivileged() {
				// Use mock maps for unprivileged tests
				policyMap4 = newMockPolicyMap()
			} else {
				// Use real maps for privileged tests
				policyMap4, _, _ = realSRv6Maps(t)
			}

			dp := &DataPlane{
				policyMap4: policyMap4,
			}

			for _, update := range tt.updates {
				dp.ProcessUpdate(update)
			}

			kvs := map[srv6map.PolicyKey]types.IPv6{}
			policyMap4.IterateWithCallback(func(k *srv6map.PolicyKey, v *srv6map.PolicyValue) {
				kvs[*k] = v.SID
			})
			require.Equal(t, tt.expectedPolicyMap4, kvs)
		})
	}
}

func TestDataPlane_EndDT4(t *testing.T) {
	sid0 := netip.MustParseAddr("2001:db8::1")
	sid1 := netip.MustParseAddr("2001:db8::2")

	endDT4Route0 := &rib.Route{
		Prefix: netip.PrefixFrom(sid0, 128),
		NextHop: &rib.EndDT4{
			VRFID: 1,
		},
	}

	endDT4Route1 := &rib.Route{
		Prefix: netip.PrefixFrom(sid1, 128),
		NextHop: &rib.EndDT4{
			VRFID: 2,
		},
	}

	endDT4Route2 := &rib.Route{
		Prefix: netip.PrefixFrom(sid0, 128),
		NextHop: &rib.EndDT4{
			VRFID: 3,
		},
	}

	invalidEndDT4Route0 := &rib.Route{
		Prefix: netip.MustParsePrefix("10.0.0.0/24"),
		NextHop: &rib.EndDT4{
			VRFID: 3,
		},
	}

	invalidEndDT4Route1 := &rib.Route{
		Prefix: netip.PrefixFrom(sid0, 128),
		NextHop: &rib.EndDT4{
			VRFID: 0,
		},
	}

	tests := []struct {
		name           string
		updates        []*rib.RIBUpdate
		expectedSIDMap map[srv6map.SIDKey]uint32
	}{
		{
			name: "New Route",
			updates: []*rib.RIBUpdate{
				{
					VRFID:   0,
					NewBest: endDT4Route0,
				},
			},
			expectedSIDMap: map[srv6map.SIDKey]uint32{
				{SID: sid0.As16()}: 1,
			},
		},
		{
			name: "Two Routes",
			updates: []*rib.RIBUpdate{
				{
					VRFID:   0,
					NewBest: endDT4Route0,
				},
				{
					VRFID:   0,
					NewBest: endDT4Route1,
				},
			},
			expectedSIDMap: map[srv6map.SIDKey]uint32{
				{SID: sid0.As16()}: 1,
				{SID: sid1.As16()}: 2,
			},
		},
		{
			name: "Update Route",
			updates: []*rib.RIBUpdate{
				{
					VRFID:   0,
					NewBest: endDT4Route0,
				},
				{
					VRFID:   0,
					OldBest: endDT4Route0,
					NewBest: endDT4Route2,
				},
			},
			expectedSIDMap: map[srv6map.SIDKey]uint32{
				{SID: sid0.As16()}: 3,
			},
		},
		{
			name: "New Route to Invalid VRF",
			updates: []*rib.RIBUpdate{
				{
					VRFID:   1,
					NewBest: endDT4Route0,
				},
			},
			expectedSIDMap: map[srv6map.SIDKey]uint32{},
		},
		{
			name: "New Invalid IPv4 Route",
			updates: []*rib.RIBUpdate{
				{
					VRFID:   0,
					NewBest: invalidEndDT4Route0,
				},
			},
			expectedSIDMap: map[srv6map.SIDKey]uint32{},
		},
		{
			name: "New Invalid Route with Default VRF",
			updates: []*rib.RIBUpdate{
				{
					VRFID:   0,
					NewBest: invalidEndDT4Route1,
				},
			},
			expectedSIDMap: map[srv6map.SIDKey]uint32{},
		},
		{
			name: "Delete Route",
			updates: []*rib.RIBUpdate{
				{
					VRFID:   0,
					NewBest: endDT4Route0,
				},
				{
					VRFID:   0,
					OldBest: endDT4Route0,
				},
			},
			expectedSIDMap: map[srv6map.SIDKey]uint32{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sidMap sidMap
			if !testutils.IsPrivileged() {
				// Use mock maps for unprivileged tests
				sidMap = newMockSidMap()
			} else {
				// Use real maps for privileged tests
				_, _, sidMap = realSRv6Maps(t)
			}

			dp := &DataPlane{
				sidMap: sidMap,
			}

			for _, update := range tt.updates {
				dp.ProcessUpdate(update)
			}

			kvs := map[srv6map.SIDKey]uint32{}
			sidMap.IterateWithCallback(func(k *srv6map.SIDKey, v *srv6map.SIDValue) {
				kvs[*k] = v.VRFID
			})
			require.Equal(t, tt.expectedSIDMap, kvs)
		})
	}
}
