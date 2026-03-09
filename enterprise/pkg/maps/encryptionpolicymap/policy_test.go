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
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
)

// encryptionPolicyIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an encryption policy map.
type encryptionPolicyIterateCallback func(*EncryptionPolicyKey, *EncryptionPolicyVal)

// iterateWithCallback iterates through all the keys/values of an encryption policy
// map, passing each key/value pair to the cb callback.
func iterateWithCallback(m *PolicyMap, cb encryptionPolicyIterateCallback) error {
	return m.Map.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*EncryptionPolicyKey)
		value := v.(*EncryptionPolicyVal)

		cb(key, value)
	})
}

func TestNewEncryptionPolicyKeyPrefixLengths(t *testing.T) {
	tests := []struct {
		name              string
		subjectID         uint32
		peerID            uint32
		proto             uint8
		port              uint16
		expectedPrefixLen uint32
	}{
		{
			name:      "all-zero wildcard",
			subjectID: 0, peerID: 0, proto: 0, port: 0,
			expectedPrefixLen: 0,
		},
		{
			name:      "subject+peer",
			subjectID: 100, peerID: 200, proto: 0, port: 0,
			expectedPrefixLen: 64,
		},
		{
			name:      "subject+peer+proto",
			subjectID: 100, peerID: 200, proto: 6, port: 0,
			expectedPrefixLen: 80,
		},
		{
			name:      "fully specific",
			subjectID: 100, peerID: 200, proto: 6, port: 8080,
			expectedPrefixLen: 96,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := NewEncryptionPolicyKey(tt.subjectID, tt.peerID, tt.proto, tt.port)
			assert.Equal(t, tt.expectedPrefixLen, key.Prefixlen, "prefix length mismatch")
			assert.Equal(t, tt.subjectID, key.SubjectIdentity, "subject identity mismatch")
			assert.Equal(t, tt.peerID, key.PeerIdentity, "peer identity mismatch")
			assert.Equal(t, uint16(tt.proto), key.Nexthdr, "nexthdr mismatch")
		})
	}
}

func TestPrivilegedPolicyMap(t *testing.T) {
	testutils.PrivilegedTest(t)
	log := hivetest.Logger(t)

	bpf.CheckOrMountFS(log, "")
	assert.NoError(t, rlimit.RemoveMemlock())

	encryptionPolicyMap := createPolicyMap(hivetest.Lifecycle(t), defaultEncryptionPolicyMapConfig, ebpf.PinNone)

	key := NewEncryptionPolicyKey(10, 20, 4, 12345)
	val := NewEncryptionPolicyValRaw(1)
	err := encryptionPolicyMap.Map.Update(&key, &val)
	assert.NoError(t, err)

	key = NewEncryptionPolicyKey(10, 20, 0, 0)
	val = NewEncryptionPolicyValRaw(2)
	err = encryptionPolicyMap.Map.Update(&key, &val)
	assert.NoError(t, err)

	iterateWithCallback(encryptionPolicyMap, func(k *EncryptionPolicyKey, v *EncryptionPolicyVal) {
		fmt.Printf("Key: (subject: %d, peer: %d, proto: %d, port: %d), Val: %d\n", k.SubjectIdentity, k.PeerIdentity, k.Nexthdr, k.PeerPortNetwork, v.Flags)
	})

	key = NewEncryptionPolicyKey(10, 20, 4, 12345)
	mVal, err := encryptionPolicyMap.Map.Lookup(&key)
	assert.NoError(t, err)
	assert.Equal(t, mVal.(*EncryptionPolicyVal).Flags, policyEntryFlags(1))

	key = NewEncryptionPolicyKey(10, 20, 4, 12345)
	err = encryptionPolicyMap.Map.Delete(&key)
	assert.NoError(t, err)

	iterateWithCallback(encryptionPolicyMap, func(k *EncryptionPolicyKey, v *EncryptionPolicyVal) {
		fmt.Printf("Key: (subject: %d, peer: %d, proto: %d, port: %d), Val: %d\n", k.SubjectIdentity, k.PeerIdentity, k.Nexthdr, k.PeerPortNetwork, v.Flags)
	})

	key = NewEncryptionPolicyKey(10, 20, 4, 12345)
	mVal, err = encryptionPolicyMap.Map.Lookup(&key)
	assert.NoError(t, err)
	assert.Equal(t, mVal.(*EncryptionPolicyVal).Flags, policyEntryFlags(2))

	key = NewEncryptionPolicyKey(10, 20, 0, 0)
	err = encryptionPolicyMap.Map.Delete(&key)
	assert.NoError(t, err)

	key = NewEncryptionPolicyKey(10, 20, 4, 12345)
	_, err = encryptionPolicyMap.Map.Lookup(&key)
	assert.Error(t, err)
}
