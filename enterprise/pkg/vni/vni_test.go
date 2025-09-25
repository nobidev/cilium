// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package vni

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVNI(t *testing.T) {
	t.Run("FromUint32", func(t *testing.T) {
		// Bounds check
		v, err := FromUint32(0)
		require.NoError(t, err, "Failed to construct 0 VNI")
		require.Equal(t, uint32(0), v.AsUint32(), "Unexpected output of AsUint32")
		require.True(t, v.IsValid(), "Constructed VNI must be valid")

		v, err = FromUint32(0xffffff)
		require.NoError(t, err, "Failed to construct 2^24-1 VNI")
		require.Equal(t, uint32(0xffffff), v.AsUint32(), "Unexpected output of AsUint32")
		require.True(t, v.IsValid(), "Constructed VNI must be valid")

		v, err = FromUint32(0xffff)
		require.NoError(t, err, "Failed to construct 2^16 VNI")
		require.Equal(t, uint32(0xffff), v.AsUint32(), "Unexpected output of AsUint32")
		require.True(t, v.IsValid(), "Constructed VNI must be valid")

		// Out of range
		v, err = FromUint32(0x1000000)
		require.ErrorIs(t, err, ErrOutOfRange, "Unexpected result of out-of-range construction")
		require.False(t, v.IsValid(), "Failed construction must produce invalid VNI")
	})
	t.Run("Parse", func(t *testing.T) {
		// Bounds check with decimal
		v, err := Parse("0")
		require.NoError(t, err, "Failed to construct 0 VNI")
		require.Equal(t, uint32(0), v.AsUint32(), "Unexpected output of AsUint32")
		require.True(t, v.IsValid(), "Constructed VNI must be valid")

		v, err = Parse("16777215")
		require.NoError(t, err, "Failed to construct 2^24-1 VNI")
		require.Equal(t, uint32(0xffffff), v.AsUint32(), "Unexpected output of AsUint32")
		require.True(t, v.IsValid(), "Constructed VNI must be valid")

		v, err = Parse("65535")
		require.NoError(t, err, "Failed to construct 2^16 VNI")
		require.Equal(t, uint32(0xffff), v.AsUint32(), "Unexpected output of AsUint32")
		require.True(t, v.IsValid(), "Constructed VNI must be valid")

		// Hex
		v, err = Parse("0xffff")
		require.NoError(t, err, "Failed to construct 2^16 VNI with hex")
		require.Equal(t, uint32(0xffff), v.AsUint32(), "Unexpected output of AsUint32")
		require.True(t, v.IsValid(), "Constructed VNI must be valid")

		// Out of range
		v, err = Parse("16777216")
		require.Error(t, err, "Unexpected result of out-of-range construction")
		require.False(t, v.IsValid(), "Failed construction must produce invalid VNI")

	})
	t.Run("Validity and Equality", func(t *testing.T) {
		valid := MustFromUint32(0)
		require.True(t, valid.IsValid(), "Constructed VNI must be valid")

		invalid := VNI{}
		require.False(t, invalid.IsValid(), "VNI constructed without constructor must be invalid")
		require.NotEqual(t, valid, invalid, "Valid VNI 0 must not be equal to invalid VNI 0")

		v0 := MustFromUint32(1)
		v1 := MustFromUint32(1)
		require.Equal(t, v0, v1, "Valid VNIs with same value must be equal")

		v0 = MustFromUint32(1)
		v1 = MustFromUint32(2)
		require.NotEqual(t, v0, v1, "Valid VNIs with different value must not be equal")

		v0 = VNI{}
		v1 = VNI{}
		require.Equal(t, v0, v1, "Invalid VNIs must be equal")
	})
	t.Run("Map Key", func(t *testing.T) {
		v0 := MustFromUint32(1)
		v1 := MustFromUint32(1)
		m := map[VNI]int{
			v0: 1,
		}
		require.Equal(t, 1, m[v1], "Map lookup failed")
	})
}
