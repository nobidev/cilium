// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmapha

import (
	"context"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/stream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

func TestPrivilegedEgressCTMap(t *testing.T) {
	testutils.PrivilegedTest(t)
	log := hivetest.Logger(t)

	bpf.CheckOrMountFS(log, "")
	assert.NoError(t, rlimit.RemoveMemlock())

	egressCTMap := createCtMap(hivetest.Lifecycle(t), log, ebpf.PinNone)

	// Create the following entry,
	//  - Egress CT:
	//      Src IP         Dst IP         Proto   Src Port   Dst Port
	//      192.168.61.11  192.168.61.12  6       38193      80
	//
	// and check that it gets GC-ed if the following CT entry is purged:
	//	- CT:	TCP OUT 192.168.61.11:38193 -> 192.168.61.12:80 <..>
	//
	// Note that the source and destination IPs are reversed.

	ctKey := &EgressCtKey4{
		TupleKey4: tuple.TupleKey4{
			SourceAddr: types.IPv4{192, 168, 61, 11},
			DestAddr:   types.IPv4{192, 168, 61, 12},
			SourcePort: 0x3195,
			DestPort:   0x50,
			NextHeader: u8proto.TCP,
			Flags:      tuple.TUPLE_F_OUT,
		},
	}
	ctVal := &EgressCtVal4{}

	err := egressCTMap.Update(ctKey, ctVal, 0)
	require.NoError(t, err)

	observable4, next4, complete4 := stream.Multicast[ctmap.GCEvent]()
	observable4.Observe(context.Background(),
		func(event ctmap.GCEvent) {
			PurgeEgressCTEntry(egressCTMap, event.Key)
		},
		func(err error) {})

	next4(ctmap.GCEvent{
		Key: &ctmap.CtKey4Global{
			TupleKey4Global: tuple.TupleKey4Global{
				TupleKey4: tuple.TupleKey4{
					SourceAddr: types.IPv4{192, 168, 61, 12},
					DestAddr:   types.IPv4{192, 168, 61, 11},
					SourcePort: 0x3195,
					DestPort:   0x50,
					NextHeader: u8proto.TCP,
					Flags:      tuple.TUPLE_F_OUT,
				},
			},
		},
		Entry: &ctmap.CtEntry{
			Packets:  1,
			Bytes:    216,
			Lifetime: 37459,
		},
		NatMap: nil,
	})
	complete4(nil)

	var val EgressCtVal4
	err = egressCTMap.Lookup(ctKey, &val)
	assert.ErrorIs(t, err, ebpf.ErrKeyNotExist)
}
