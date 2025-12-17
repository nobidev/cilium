//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package privnet

import (
	"context"
	"encoding"
	"fmt"
	"log/slog"
	"net/netip"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb/reconciler"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"

	privnetcfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/policy"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/identity"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/types"
)

const (
	cidrIdentitiyMapName = "cilium_privnet_cidr_identity"
)

type CIDRIdentityKey struct {
	PrefixLen uint32     `align:"lpm_key"`
	Family    uint8      `align:"family"`
	_         [3]uint8   `align:"pad"`
	Address   types.IPv6 `align:"$union0"`
}

type CIDRIdentityVal struct {
	SecIdentity uint32 `align:"sec_identity"`
}

var _ KeyValue = &CIDRIdentityKeyVal{}

type CIDRIdentityKeyVal struct {
	Key CIDRIdentityKey
	Val CIDRIdentityVal
}

type CIDRIdentityMap struct {
	*bpf.Map
}

func (c CIDRIdentityMap) Ops() reconciler.Operations[*CIDRIdentityKeyVal] {
	return bpf.NewMapOps[*CIDRIdentityKeyVal](c.Map)
}

// BinaryKey implements bpf.KeyValue.
func (c *CIDRIdentityKeyVal) BinaryKey() encoding.BinaryMarshaler {
	return bpf.StructBinaryMarshaler{Target: &c.Key}
}

// BinaryValue implements bpf.KeyValue.
func (c *CIDRIdentityKeyVal) BinaryValue() encoding.BinaryMarshaler {
	return bpf.StructBinaryMarshaler{Target: &c.Val}
}

func (c *CIDRIdentityKeyVal) MapKey() bpf.MapKey {
	return &c.Key
}

func (c *CIDRIdentityKeyVal) MapValue() bpf.MapValue {
	return &c.Val
}

func getCIDRIdentityStaticPrefixBits() uint32 {
	staticMatchSize := unsafe.Sizeof(CIDRIdentityKey{})
	staticMatchSize -= unsafe.Sizeof(CIDRIdentityKey{}.PrefixLen)
	staticMatchSize -= unsafe.Sizeof(CIDRIdentityKey{}.Address)
	return uint32(staticMatchSize) * 8
}

func NewCIDRIdentityKey(prefix netip.Prefix) CIDRIdentityKey {
	family, addr := fromAddr(prefix.Addr())
	prefixLen := getCIDRIdentityStaticPrefixBits() + uint32(prefix.Bits())

	return CIDRIdentityKey{
		PrefixLen: prefixLen,
		Family:    family,
		Address:   addr,
	}
}

func (c *CIDRIdentityKey) ToPrefix() netip.Prefix {
	return netip.PrefixFrom(toAddr(c.Family, c.Address), int(c.PrefixLen)-int(getCIDRIdentityStaticPrefixBits()))
}

func (c *CIDRIdentityKey) String() string {
	return c.ToPrefix().String()
}

func (c *CIDRIdentityKey) New() bpf.MapKey {
	return &CIDRIdentityKey{}
}

func NewCIDRIdentityVal(identity identity.NumericIdentity) CIDRIdentityVal {
	return CIDRIdentityVal{
		SecIdentity: identity.Uint32(),
	}
}

func (i *CIDRIdentityVal) String() string {
	return identity.NumericIdentity(i.SecIdentity).String()
}

func (i *CIDRIdentityVal) New() bpf.MapValue {
	return &CIDRIdentityVal{}
}

func (c CIDRIdentityMap) ToInterface() Map[*CIDRIdentityKeyVal] {
	return &c
}

func (c *CIDRIdentityMap) List() ([]string, error) {
	var data []string

	_, err := c.dumpBatch(func(key *CIDRIdentityKey, val *CIDRIdentityVal) {
		data = append(data, fmt.Sprintf("%s -> %s", key.String(), val.String()))
	})

	return data, err
}

func (c *CIDRIdentityMap) dumpBatch(fn func(*CIDRIdentityKey, *CIDRIdentityVal)) (count int, err error) {
	iter := bpf.NewBatchIterator[CIDRIdentityKey, CIDRIdentityVal](c.Map)
	for key, entry := range iter.IterateAll(context.Background()) {
		count++
		fn(key, entry)
	}
	return count, nil
}

func OpenPrivNetCIDRIdentityMap(logger *slog.Logger) (*CIDRIdentityMap, error) {
	path := bpf.MapPath(logger, cidrIdentitiyMapName)

	m, err := bpf.OpenMap(path, &CIDRIdentityKey{}, &CIDRIdentityVal{})
	if err != nil {
		return nil, err
	}

	return &CIDRIdentityMap{Map: m}, nil
}

var RestoredCIDROwner = ipcacheTypes.NewResourceID(ipcacheTypes.ResourceKindDaemon, "", "isovalent-privnet-cidr-restored")

// createCIDRIdentityMap restores CIDR entries from the old and creates a new CIDRIdentity BPF map
func createCIDRIdentityMap(in struct {
	cell.In

	Config          privnetcfg.Config
	MapConfig       Config
	RestorerPromise promise.Promise[endpointstate.Restorer]

	Lifecycle cell.Lifecycle
	JopGroup  job.Group

	Observer policy.CIDRQueuer
}) bpf.MapOut[Map[*CIDRIdentityKeyVal]] {
	bpfMap := bpf.NewMap(
		cidrIdentitiyMapName,
		ebpf.LPMTrie,
		&CIDRIdentityKey{},
		&CIDRIdentityVal{},
		int(in.MapConfig.CIDRIdentityMapSize),
		unix.BPF_F_NO_PREALLOC,
	)

	in.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			if !in.Config.Enabled {
				// clean-up stale maps if previously enabled
				return bpfMap.Unpin()
			}

			// Emit CIDRMetadata events based on pre-start BPF map
			restoredPrefixes := sets.Set[netip.Prefix]{}
			err := bpfMap.DumpWithCallbackIfExists(func(key bpf.MapKey, value bpf.MapValue) {
				prefix := key.(*CIDRIdentityKey).ToPrefix()
				sec := value.(*CIDRIdentityVal).SecIdentity

				restoredPrefixes.Insert(prefix)
				in.Observer.Queue(policy.EventUpsert, policy.CIDRMetadata{
					Prefix: prefix,
					Owner:  RestoredCIDROwner,
					Metadata: policy.CIDRRestored{
						Identity: identity.NumericIdentity(sec),
					},
				})
			})
			if err != nil {
				return fmt.Errorf("failed to restore cidr-identities map: %w", err)
			}
			// DumpWithCallbackIfExists leaves the map open - we need to close it before we can re-create it
			bpfMap.Close()

			in.Observer.Queue(policy.EventRestored, policy.CIDRMetadata{})

			// Make sure restored identities are released after endpoints have been restored.
			// The cidr identity allocator blocks endpoint regeneration, so if endpoints have been
			// restored, it is guaranteed that the cidr identity allocator has processed the
			// updates emitted above.
			in.JopGroup.Add(job.OneShot("release-restored-cidrs", func(ctx context.Context, health cell.Health) error {
				health.OK("Waiting for endpoint restoration")
				restorer, err := in.RestorerPromise.Await(ctx)
				if err != nil {
					return err
				}

				err = restorer.WaitForEndpointRestore(ctx)
				if err != nil {
					return err
				}

				health.OK("Releasing restored identities")
				for prefix := range restoredPrefixes {
					in.Observer.Queue(policy.EventDelete, policy.CIDRMetadata{
						Prefix:   prefix,
						Owner:    RestoredCIDROwner,
						Metadata: policy.CIDRRestored{},
					})
				}

				return nil
			}))

			err = bpfMap.Recreate()
			if err != nil {
				return fmt.Errorf("failed to create cidr-identities map: %w", err)
			}

			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			if !in.Config.Enabled {
				return nil
			}

			return bpfMap.Close()
		},
	})

	return bpf.NewMapOut(Map[*CIDRIdentityKeyVal](CIDRIdentityMap{Map: bpfMap}))
}
