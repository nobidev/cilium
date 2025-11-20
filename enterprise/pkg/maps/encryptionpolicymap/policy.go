//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package encryptionpolicymap

import (
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"

	encryptionPolicyTypes "github.com/cilium/cilium/enterprise/pkg/encryption/policy/types"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
)

const (
	PolicyMapName = "cilium_encryption_policy_map"

	sizeofPolicyKey    = int(unsafe.Sizeof(EncryptionPolicyKey{}))
	sizeofPrefixlen    = int(unsafe.Sizeof(EncryptionPolicyKey{}.Prefixlen))
	sizeofPeerIdentity = int(unsafe.Sizeof(EncryptionPolicyKey{}.PeerIdentity))
	sizeofNexthdr      = int(unsafe.Sizeof(EncryptionPolicyKey{}.Nexthdr))
	sizeofPeerPort     = int(unsafe.Sizeof(EncryptionPolicyKey{}.PeerPortNetwork))

	PeerIdentityBits = uint32(sizeofPeerIdentity) * 8
	NexthdrBits      = uint32(sizeofNexthdr) * 8
	PeerPortBits     = uint32(sizeofPeerPort) * 8
	FullPrefixBits   = NexthdrBits + PeerPortBits
	// PolicyStaticPrefixBits represents the size in bits of the static
	// prefix part of an encryption policy key (i.e. the source IP).
	PolicyStaticPrefixBits = uint32(sizeofPolicyKey-sizeofPrefixlen)*8 - FullPrefixBits

	MaxPolicyEntries = 1 << 14
)

type EncryptionPolicyKey struct {
	Prefixlen       uint32 `align:"lpm_key"`
	SubjectIdentity uint32 `align:"src_sec_identity"`
	PeerIdentity    uint32 `align:"dst_sec_identity"`
	Nexthdr         uint16 `align:"protocol"`
	PeerPortNetwork uint16 `align:"port"` // In network byte-order
}

type policyEntryFlags uint8

type EncryptionPolicyVal struct {
	Flags policyEntryFlags
}

type MapConfig struct {
	// EncryptionPolicyMapMax is the maximum number of entries
	// allowed in the BPF encryption policy map.
	EncryptionPolicyMapMax int
}

var defaultEncryptionPolicyMapConfig = MapConfig{
	EncryptionPolicyMapMax: MaxPolicyEntries,
}

func (cfg MapConfig) Flags(flags *pflag.FlagSet) {
	flags.Int("encryption-policy-map-max", cfg.EncryptionPolicyMapMax, "Maximum number of entries in encryption policy map")
}

type encryptionPolicyParams struct {
	cell.In

	Lifecycle cell.Lifecycle

	encryptionPolicyTypes.Config
	MapConfig
}

// PolicyMap is the internal representation of an encryption policy map.
type PolicyMap struct {
	*bpf.Map
}

func createPolicyMapFromConfig(p encryptionPolicyParams) (out struct {
	cell.Out

	bpf.MapOut[*PolicyMap]
	defines.NodeOut
}) {
	if !p.EnableEncryptionPolicy {
		return
	}

	out.NodeDefines = map[string]string{
		"ENCRYPTION_POLICY_MAP_SIZE": fmt.Sprint(p.EncryptionPolicyMapMax),
	}
	out.MapOut = bpf.NewMapOut(createPolicyMap(p.Lifecycle, p.MapConfig, ebpf.PinByName))
	return
}

func createPolicyMap(lc cell.Lifecycle, cfg MapConfig, pinning ebpf.PinType) *PolicyMap {
	m := bpf.NewMap(
		PolicyMapName,
		ebpf.LPMTrie,
		&EncryptionPolicyKey{},
		&EncryptionPolicyVal{},
		cfg.EncryptionPolicyMapMax,
		unix.BPF_F_NO_PREALLOC,
	)

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

	return &PolicyMap{m}
}

func (k *EncryptionPolicyKey) New() bpf.MapKey { return &EncryptionPolicyKey{} }

func (k *EncryptionPolicyKey) String() string {
	return fmt.Sprintf("prefixlen=%-3d subject=%-5d peer=%-5d proto=%-2d port=%-5d",
		k.Prefixlen,
		k.SubjectIdentity,
		k.PeerIdentity,
		k.Nexthdr,
		byteorder.NetworkToHost16(k.PeerPortNetwork),
	)
}

func NewEncryptionPolicyKey(subjectID, peerID uint32, proto uint8, port uint16) EncryptionPolicyKey {
	// for now this doesn't allow/expect wildcarding the peer identity.
	prefixLen := PolicyStaticPrefixBits
	if proto != 0 || port != 0 {
		prefixLen += NexthdrBits
		if port != 0 {
			prefixLen += PeerPortBits
		}
	}
	return EncryptionPolicyKey{
		Prefixlen:       prefixLen,
		SubjectIdentity: subjectID,
		PeerIdentity:    peerID,
		Nexthdr:         uint16(proto),
		PeerPortNetwork: byteorder.HostToNetwork16(port),
	}
}

func (v *EncryptionPolicyVal) New() bpf.MapValue { return &EncryptionPolicyVal{} }

func (v *EncryptionPolicyVal) String() string {
	return fmt.Sprintf("flags=0x%04X", v.Flags)
}

func NewEncryptionPolicyVal(flags policyEntryFlags) EncryptionPolicyVal {
	return EncryptionPolicyVal{Flags: flags}
}
