//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package types

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewSIDStructure(t *testing.T) {
	tests := []struct {
		name      string
		lb        uint8
		ln        uint8
		f         uint8
		a         uint8
		structure SIDStructure
		errorStr  string
	}{
		{
			name: "ValidStructureF3216",
			lb:   32, ln: 16, f: 16, a: 0,
			structure: SIDStructure{32, 16, 16, 0},
		},
		{
			name: "ValidStructureCiliumLegacy",
			lb:   128, ln: 0, f: 0, a: 0,
			structure: SIDStructure{128, 0, 0, 0},
		},
		{
			name: "NonByteAlignedLocatorBlock",
			lb:   33, ln: 16, f: 16, a: 0,
			errorStr: "SID structure bits must be byte-aligned",
		},
		{
			name: "NonByteAlignedLocatorNode",
			lb:   32, ln: 17, f: 16, a: 0,
			errorStr: "SID structure bits must be byte-aligned",
		},
		{
			name: "NonByteAlignedFunction",
			lb:   32, ln: 16, f: 17, a: 0,
			errorStr: "SID structure bits must be byte-aligned",
		},
		{
			name: "Over128Bit",
			lb:   64, ln: 64, f: 32, a: 0,
			errorStr: "total number of bits exceeds 128",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ss, err := NewSIDStructure(test.lb, test.ln, test.f, test.a)
			if test.errorStr != "" {
				require.Error(t, err)
				require.Equal(t, test.errorStr, err.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, test.structure, ss)
			}
		})
	}
}

func TestNewLocator(t *testing.T) {
	tests := []struct {
		name     string
		prefix   netip.Prefix
		locator  Locator
		errorStr string
	}{
		{
			name:   "ValidLocator",
			prefix: netip.MustParsePrefix("fd00::/48"),
			locator: Locator{
				Prefix: netip.MustParsePrefix("fd00::/48"),
			},
		},
		{
			name:     "InvalidPrefix",
			prefix:   netip.MustParsePrefix("10.0.0.0/24"),
			errorStr: "locator prefix must be IPv6",
		},
		{
			name:     "ByteUnalignedPrefix",
			prefix:   netip.MustParsePrefix("fd00::/49"),
			errorStr: "locator prefix length must be byte-aligned",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewLocator(test.prefix)
			if test.errorStr != "" {
				require.Error(t, err)
				require.Equal(t, test.errorStr, err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestNewSID(t *testing.T) {
	tests := []struct {
		name     string
		addr     netip.Addr
		sid      SID
		errorStr string
	}{
		{
			name: "ValidSID",
			addr: netip.MustParseAddr("fd00::"),
			sid: SID{
				Addr: netip.MustParseAddr("fd00::"),
			},
		},
		{
			name:     "InvalidAddr",
			addr:     netip.MustParseAddr("10.0.0.0"),
			sid:      SID{},
			errorStr: "SID must be IPv6",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sid, err := NewSID(test.addr)
			if test.errorStr != "" {
				require.Equal(t, test.errorStr, err.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, test.sid, sid)
			}
		})
	}
}

func TestTranspose(t *testing.T) {
	addr := netip.MustParseAddr("fd00:1234:5678:9abc:deff:edcb:a987:6543")
	sid := MustNewSID(addr)

	tt := []struct {
		name          string
		offset        uint8
		length        uint8
		expectedLabel uint32
		expectedSID   []byte
	}{
		{
			name:          "Valid (TO: 64, TL: 16)",
			offset:        64,
			length:        16,
			expectedLabel: 0xdeff0,
			expectedSID: func() []byte {
				sid := addr.AsSlice()
				sid[8] = 0
				sid[9] = 0
				return sid
			}(),
		},
		{
			name:          "Valid (TO: 48, TL: 16)",
			offset:        48,
			length:        16,
			expectedLabel: 0x9abc0,
			expectedSID: func() []byte {
				sid := addr.AsSlice()
				sid[6] = 0
				sid[7] = 0
				return sid
			}(),
		},
		{
			name:          "Non-byte-aligned transposition length and offset",
			offset:        60,
			length:        20,
			expectedLabel: 0xcdeff,
			expectedSID: func() []byte {
				sid := addr.AsSlice()
				sid[7] = 0xb0
				sid[8] = 0x00
				sid[9] = 0x00
				return sid
			}(),
		},
		{
			name:          "Non-4bit-aligned transposition length and offset",
			offset:        63,
			length:        18,
			expectedLabel: 0x6f7fc,
			expectedSID: func() []byte {
				sid := addr.AsSlice()
				sid[7] = 0xbc
				sid[8] = 0x00
				sid[9] = 0x00
				sid[10] = 0x6d
				return sid
			}(),
		},
		{
			name:          "Less than 1byte transposition length",
			offset:        64,
			length:        7,
			expectedLabel: 0x1bc000,
			expectedSID: func() []byte {
				sid := addr.AsSlice()
				sid[8] = 0x00
				return sid
			}(),
		},
		{
			name:          "1byte transposition crosses the byte boundary",
			offset:        60,
			length:        8,
			expectedLabel: 0xcd000,
			expectedSID: func() []byte {
				sid := addr.AsSlice()
				sid[7] = 0xb0
				sid[8] = 0x0e
				return sid
			}(),
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			label, transposedSID, err := sid.Transpose(test.offset, test.length)
			require.NoError(t, err)
			require.Equal(t, test.expectedLabel, label)
			require.Equal(t, test.expectedSID, transposedSID)
		})
	}
}

func TestNewSIDFromTransposed(t *testing.T) {
	sidTmpl := [16]byte{0xfd, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43}
	expectedSID := MustNewSID(netip.MustParseAddr("fd00:1234:5678:9abc:deff:edcb:a987:6543"))

	tt := []struct {
		name   string
		sid    []byte
		label  uint32
		offset uint8
		length uint8
	}{
		{
			name:   "Not transposed",
			sid:    sidTmpl[:],
			label:  0,
			offset: 0,
			length: 0,
		},
		{
			name: "Valid (TO: 64, TL: 16)",
			sid: func() []byte {
				sid := [16]byte{}
				copy(sid[:], sidTmpl[:])
				sid[8] = 0
				sid[9] = 0
				return sid[:]
			}(),
			label:  0x000deff0,
			offset: 64,
			length: 16,
		},
		{
			name: "Valid (TO: 48, TL: 16)",
			sid: func() []byte {
				sid := [16]byte{}
				copy(sid[:], sidTmpl[:])
				sid[6] = 0
				sid[7] = 0
				return sid[:]
			}(),
			label:  0x0009abc0,
			offset: 48,
			length: 16,
		},
		{
			name: "Non-byte-aligned transposition length and offset",
			sid: func() []byte {
				sid := [16]byte{}
				copy(sid[:], sidTmpl[:])
				sid[7] = 0xb0
				sid[8] = 0x00
				sid[9] = 0x00
				return sid[:]
			}(),
			label:  0x000cdeff,
			offset: 60,
			length: 20,
		},
		{
			name: "Non-4bit-aligned transposition length and offset",
			sid: func() []byte {
				sid := [16]byte{}
				copy(sid[:], sidTmpl[:])
				sid[7] = 0xbc // 1100
				sid[8] = 0x00
				sid[9] = 0x00
				sid[10] = 0x6d
				return sid[:]
			}(),
			label:  0x0006f7fc,
			offset: 63,
			length: 18,
		},
		{
			name: "Less than 1byte transposition length",
			sid: func() []byte {
				sid := [16]byte{}
				copy(sid[:], sidTmpl[:])
				sid[8] = 0x00
				return sid[:]
			}(),
			label:  0x000de000,
			offset: 64,
			length: 7,
		},
		{
			name: "1byte transposition crosses the byte boundary",
			sid: func() []byte {
				sid := [16]byte{}
				copy(sid[:], sidTmpl[:])
				sid[7] = 0xb0
				sid[8] = 0x0e
				return sid[:]
			}(),
			label:  0x000cd000,
			offset: 60,
			length: 8,
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			sid, err := NewSIDFromTransposed(test.sid, test.label, test.offset, test.length)
			require.NoError(t, err)
			require.Equal(t, expectedSID.String(), sid.String())
		})
	}
}
