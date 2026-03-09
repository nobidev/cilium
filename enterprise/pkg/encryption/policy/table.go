//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package policy

import (
	"encoding"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/enterprise/pkg/maps/encryptionpolicymap"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/u8proto"
)

const EncryptionPolicyTableName = "encryption-policy"

var EncryptionPolicyTupleIndex = statedb.Index[*EncryptionPolicyEntry, EncryptionTuple]{
	Name: "tuple",
	FromObject: func(e *EncryptionPolicyEntry) index.KeySet {
		return index.NewKeySet(e.Key())
	},
	FromKey: EncryptionTuple.Key,
	Unique:  true,
}

var EncryptionPolicyRuleKeyIndex = statedb.Index[*EncryptionPolicyEntry, RuleKey]{
	Name: "rule-key",
	FromObject: func(e *EncryptionPolicyEntry) index.KeySet {
		keys := make([]index.Key, len(e.Owners))
		for i, o := range e.Owners {
			keys[i] = index.Stringer(o.Key)
		}
		return index.NewKeySet(keys...)
	},
	FromKey: index.Stringer[RuleKey],
}

func NewEncryptionPolicyTable(db *statedb.DB) (statedb.RWTable[*EncryptionPolicyEntry], error) {
	return statedb.NewTable(
		db,
		EncryptionPolicyTableName,
		EncryptionPolicyTupleIndex,
		EncryptionPolicyRuleKeyIndex,
	)
}

// RuleKey uniquely identifies an encryptionRule. It contains the Kubernetes
// resource name, the index of this particular rule within the policy, and
// a monotonically increasing revision number which is always bumped whenever
// a rule change is detected.
type RuleKey struct {
	Resource resource.Key
	Index    uint
	Revision uint64
}

func (e RuleKey) String() string {
	return fmt.Sprintf("%s[%d] (rev %d)",
		e.Resource.String(),
		e.Index,
		e.Revision,
	)
}

// RuleOwner associates a RuleKey with an encrypt preference.
// When multiple owners exist for the same tuple, encrypt=true takes precedence
// (security-first: encrypt wins).
type RuleOwner struct {
	Key     RuleKey
	Encrypt bool
}

func (o RuleOwner) String() string {
	return fmt.Sprintf("%s encrypt=%t", o.Key.String(), o.Encrypt)
}

// EncryptionTuple contains an encryption policy pair to be inserted into the
// BPF map
type EncryptionTuple struct {
	Subject identity.NumericIdentity
	Peer    identity.NumericIdentity
	Port    uint16
	Proto   u8proto.U8proto
}

// Key returns the StateDB key for EncryptionTuple k
func (k EncryptionTuple) Key() index.Key {
	sep := []byte{'+'}
	key := slices.Concat(
		index.Uint32(k.Subject.Uint32()), sep,
		index.Uint32(k.Peer.Uint32()), sep,
		index.Uint16(k.Port), sep,
		[]byte{uint8(k.Proto)},
	)
	return key
}

// EncryptionPolicyEntry is object stored in the "encryption-policy" StateDB
// table. Each entry is uniquely identified by the EncryptionTuple and is
// owned by a non-empty list of rules (indexed via RuleKey).
type EncryptionPolicyEntry struct {
	EncryptionTuple

	// Owners is a list of rules that required this entry to be created.
	// Each owner tracks whether it wants the tuple to be encrypted.
	Owners []RuleOwner

	// Status is the BPF map reconciliation status
	Status reconciler.Status
}

// resolvedEncrypt returns true if any owner has Encrypt=true.
// This implements encrypt-wins conflict resolution: if any policy
// wants a tuple encrypted, it is encrypted.
func (e *EncryptionPolicyEntry) resolvedEncrypt() bool {
	for _, o := range e.Owners {
		if o.Encrypt {
			return true
		}
	}
	return false
}

func (e *EncryptionPolicyEntry) DeepCopy() *EncryptionPolicyEntry {
	return &EncryptionPolicyEntry{
		EncryptionTuple: e.EncryptionTuple,
		Owners:          slices.Clone(e.Owners),
		Status:          e.Status,
	}
}

func (e *EncryptionPolicyEntry) BinaryKey() encoding.BinaryMarshaler {
	k := encryptionpolicymap.NewEncryptionPolicyKey(
		e.Subject.Uint32(),
		e.Peer.Uint32(),
		uint8(e.Proto),
		e.Port,
	)
	return bpf.StructBinaryMarshaler{Target: &k}
}

func (e *EncryptionPolicyEntry) BinaryValue() encoding.BinaryMarshaler {
	v := encryptionpolicymap.NewEncryptionPolicyVal(e.resolvedEncrypt())
	return bpf.StructBinaryMarshaler{Target: &v}
}

func (e *EncryptionPolicyEntry) TableHeader() []string {
	return []string{
		"Subject",
		"Peer",
		"Port",
		"Proto",
		"Encrypt",
		"Owners",
		"Status",
	}
}

func (e *EncryptionPolicyEntry) TableRow() []string {
	owners := make([]string, 0, len(e.Owners))
	for _, o := range e.Owners {
		owners = append(owners, o.String())
	}

	return []string{
		e.Subject.StringID(),
		e.Peer.StringID(),
		strconv.FormatUint(uint64(e.Port), 10),
		e.Proto.String(),
		strconv.FormatBool(e.resolvedEncrypt()),
		strings.Join(owners, ","),
		e.Status.String(),
	}
}
