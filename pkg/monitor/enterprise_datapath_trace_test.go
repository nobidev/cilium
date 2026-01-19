//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package monitor

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/types"
)

func TestEnterpriseTraceNotify_Decode(t *testing.T) {

	testCases := []struct {
		name  string
		input EnterpriseTraceNotify
		fail  bool
	}{
		{
			name: "empty",
		},
		{
			name: "arbitrary",
			input: EnterpriseTraceNotify{
				TraceNotify: TraceNotify{Type: 0x00,
					ObsPoint:   0x02,
					Source:     0x03_04,
					Hash:       0x05_06_07_08,
					OrigLen:    0x09_0a_0b_0c,
					CapLen:     0x0d_0e,
					Version:    TraceNotifyVersion2,
					ExtVersion: TraceNotifyExtensionV1,
					SrcLabel:   identity.NumericIdentity(0x11_12_13_14),
					DstLabel:   identity.NumericIdentity(0x15_16_17_18),
					DstID:      0x19_1a,
					Reason:     0x1b,
					Flags:      0x1c,
					Ifindex:    0x1d_1e_1f_20,
					OrigIP: types.IPv6{
						0x21, 0x22, 0x23, 0x24,
						0x25, 0x26, 0x27, 0x28,
						0x29, 0x2a, 0x2b, 0x2c,
						0x2d, 0x2e, 0x2f, 0x30,
					},
					IPTraceID: 0x2b_2c_2d_2e_2f_30_31_32,
				},
				SrcNetID: 1337,
				DstNetID: 42,
			},
		},
		{
			name: "unknown extension",
			input: EnterpriseTraceNotify{
				TraceNotify: TraceNotify{Type: 0x00,
					ObsPoint:   0x02,
					Source:     0x03_04,
					Hash:       0x05_06_07_08,
					OrigLen:    0x09_0a_0b_0c,
					CapLen:     0x0d_0e,
					Version:    TraceNotifyVersion2,
					ExtVersion: 0xfe,
					SrcLabel:   identity.NumericIdentity(0x11_12_13_14),
					DstLabel:   identity.NumericIdentity(0x15_16_17_18),
					DstID:      0x19_1a,
					Reason:     0x1b,
					Flags:      0x1c,
					Ifindex:    0x1d_1e_1f_20,
					OrigIP: types.IPv6{
						0x21, 0x22, 0x23, 0x24,
						0x25, 0x26, 0x27, 0x28,
						0x29, 0x2a, 0x2b, 0x2c,
						0x2d, 0x2e, 0x2f, 0x30,
					},
					IPTraceID: 0x2b_2c_2d_2e_2f_30_31_32,
				},
			},
			fail: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := bytes.NewBuffer(nil)
			if err := binary.Write(buf, binary.NativeEndian, tc.input); err != nil {
				t.Fatalf("Unexpected error from Write(...); got: %v", err)
			}

			output := EnterpriseTraceNotify{}
			err := output.Decode(buf.Bytes())

			if !tc.fail && err != nil {
				t.Fatalf("Unexpected error from Decode(<bytes>); got: %v", err)
			}
			if tc.fail && err == nil {
				t.Fatalf("Expected error from Decode(<bytes>); got: %v", err)
			}

			if diff := cmp.Diff(tc.input, output); diff != "" {
				t.Errorf("Unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestEnterpriseTraceNotify_Decode_Raw(t *testing.T) {

	testCases := []struct {
		name     string
		input    []byte
		expected EnterpriseTraceNotify
		fail     bool
	}{
		{
			name: "v2extv1",
			input: []byte{
				0x00,
				0x02,
				0x04, 0x03,
				0x8, 0x7, 0x6, 0x5,
				0xc, 0xb, 0xa, 0x9,
				0xe, 0xd,
				0x2, // version 2
				0x1, // ext version 1
				0x14, 0x13, 0x12, 0x11,
				0x18, 0x17, 0x16, 0x15,
				0x1a, 0x19,
				0x1b,
				0x1c,
				0x20, 0x1f, 0x1e, 0x1d,

				0x21, 0x22, 0x23, 0x24,
				0x25, 0x26, 0x27, 0x28,
				0x29, 0x2a, 0x2b, 0x2c,
				0x2d, 0x2e, 0x2f, 0x30,

				0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0,

				0x39, 0x5, // SrcNetID
				0x2a, 0x0, // DstNetID
				0x0, 0x0, 0x0, 0x0,
			},
			expected: EnterpriseTraceNotify{
				TraceNotify: TraceNotify{Type: 0x00,
					ObsPoint:   0x02,
					Source:     0x03_04,
					Hash:       0x05_06_07_08,
					OrigLen:    0x09_0a_0b_0c,
					CapLen:     0x0d_0e,
					Version:    TraceNotifyVersion2,
					ExtVersion: TraceNotifyExtensionV1,
					SrcLabel:   identity.NumericIdentity(0x11_12_13_14),
					DstLabel:   identity.NumericIdentity(0x15_16_17_18),
					DstID:      0x19_1a,
					Reason:     0x1b,
					Flags:      0x1c,
					Ifindex:    0x1d_1e_1f_20,
					OrigIP: types.IPv6{
						0x21, 0x22, 0x23, 0x24,
						0x25, 0x26, 0x27, 0x28,
						0x29, 0x2a, 0x2b, 0x2c,
						0x2d, 0x2e, 0x2f, 0x30,
					},
					IPTraceID: 0x0,
				},
				SrcNetID: 1337,
				DstNetID: 42,
			},
		},
		{
			name: "v2extv1 - truncated",
			input: []byte{
				0x00,
				0x02,
				0x04, 0x03,
				0x8, 0x7, 0x6, 0x5,
				0xc, 0xb, 0xa, 0x9,
				0xe, 0xd,
				0x2, // version 2
				0x1, // ext version 1
				0x14, 0x13, 0x12, 0x11,
				0x18, 0x17, 0x16, 0x15,
				0x1a, 0x19,
				0x1b,
				0x1c,
				0x20, 0x1f, 0x1e, 0x1d,

				0x21, 0x22, 0x23, 0x24,
				0x25, 0x26, 0x27, 0x28,
				0x29, 0x2a, 0x2b, 0x2c,
				0x2d, 0x2e, 0x2f, 0x30,

				0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0,
				// Missing extension
			},
			expected: EnterpriseTraceNotify{
				TraceNotify: TraceNotify{Type: 0x00,
					ObsPoint:   0x02,
					Source:     0x03_04,
					Hash:       0x05_06_07_08,
					OrigLen:    0x09_0a_0b_0c,
					CapLen:     0x0d_0e,
					Version:    TraceNotifyVersion2,
					ExtVersion: TraceNotifyExtensionV1,
					SrcLabel:   identity.NumericIdentity(0x11_12_13_14),
					DstLabel:   identity.NumericIdentity(0x15_16_17_18),
					DstID:      0x19_1a,
					Reason:     0x1b,
					Flags:      0x1c,
					Ifindex:    0x1d_1e_1f_20,
					OrigIP: types.IPv6{
						0x21, 0x22, 0x23, 0x24,
						0x25, 0x26, 0x27, 0x28,
						0x29, 0x2a, 0x2b, 0x2c,
						0x2d, 0x2e, 0x2f, 0x30,
					},
					IPTraceID: 0x0,
				},
			},
			fail: true,
		},
		{
			name: "v2noext -- don't parse rubbish",
			input: []byte{
				0x00,
				0x02,
				0x04, 0x03,
				0x8, 0x7, 0x6, 0x5,
				0xc, 0xb, 0xa, 0x9,
				0xe, 0xd,
				0x2, // version 2
				0x0, // no extension
				0x14, 0x13, 0x12, 0x11,
				0x18, 0x17, 0x16, 0x15,
				0x1a, 0x19,
				0x1b,
				0x1c,
				0x20, 0x1f, 0x1e, 0x1d,

				0x21, 0x22, 0x23, 0x24,
				0x25, 0x26, 0x27, 0x28,
				0x29, 0x2a, 0x2b, 0x2c,
				0x2d, 0x2e, 0x2f, 0x30,

				0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0,

				// random data that should not be parsed
				0xde, 0xad,
				0xbe, 0xef,
				0x0, 0x0, 0x0, 0x0,
			},
			expected: EnterpriseTraceNotify{
				TraceNotify: TraceNotify{Type: 0x00,
					ObsPoint:   0x02,
					Source:     0x03_04,
					Hash:       0x05_06_07_08,
					OrigLen:    0x09_0a_0b_0c,
					CapLen:     0x0d_0e,
					Version:    TraceNotifyVersion2,
					ExtVersion: TraceNotifyExtensionDisabled,
					SrcLabel:   identity.NumericIdentity(0x11_12_13_14),
					DstLabel:   identity.NumericIdentity(0x15_16_17_18),
					DstID:      0x19_1a,
					Reason:     0x1b,
					Flags:      0x1c,
					Ifindex:    0x1d_1e_1f_20,
					OrigIP: types.IPv6{
						0x21, 0x22, 0x23, 0x24,
						0x25, 0x26, 0x27, 0x28,
						0x29, 0x2a, 0x2b, 0x2c,
						0x2d, 0x2e, 0x2f, 0x30,
					},
					IPTraceID: 0x0,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			output := EnterpriseTraceNotify{}
			err := output.Decode(tc.input)

			if !tc.fail && err != nil {
				t.Fatalf("Unexpected error from Decode(<bytes>); got: %v", err)
			}
			if tc.fail && err == nil {
				t.Fatalf("Expected error from Decode(<bytes>); got: %v", err)
			}

			if diff := cmp.Diff(tc.expected, output); diff != "" {
				t.Errorf("Unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}
