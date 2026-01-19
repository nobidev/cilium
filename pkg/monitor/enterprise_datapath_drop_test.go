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
)

func TestEnterpriseDropNotify_Decode(t *testing.T) {

	testCases := []struct {
		name  string
		input EnterpriseDropNotify
		fail  bool
	}{
		{
			name: "empty",
		},
		{
			name: "arbitrary",
			input: EnterpriseDropNotify{
				DropNotify: DropNotify{
					Type:       0x00,
					SubType:    0x01,
					Source:     0x02_03,
					Hash:       0x04_05_06_07,
					OrigLen:    0x08_09_0a_0b,
					CapLen:     0x0e_10,
					Version:    0x03,
					ExtVersion: 0x01,
					SrcLabel:   0x11_12_13_14,
					DstLabel:   0x15_16_17_18,
					DstID:      0x19_1a_1b_1c,
					Line:       0x1d_1e,
					File:       0x20,
					ExtError:   0x21,
					Ifindex:    0x22_23_24_25,
					Flags:      0x0f,
					IPTraceID:  0x99,
				},
				SrcNetID: 1337,
				DstNetID: 42,
			},
		},
		{
			name: "unknown extension",
			input: EnterpriseDropNotify{
				DropNotify: DropNotify{
					Type:       0x00,
					SubType:    0x01,
					Source:     0x02_03,
					Hash:       0x04_05_06_07,
					OrigLen:    0x08_09_0a_0b,
					CapLen:     0x0e_10,
					Version:    0x03,
					ExtVersion: 0xfe,
					SrcLabel:   0x11_12_13_14,
					DstLabel:   0x15_16_17_18,
					DstID:      0x19_1a_1b_1c,
					Line:       0x1d_1e,
					File:       0x20,
					ExtError:   0x21,
					Ifindex:    0x22_23_24_25,
					Flags:      0x0f,
					IPTraceID:  0x99,
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

			output := EnterpriseDropNotify{}
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

func TestEnterpriseDropNotify_Decode_Raw(t *testing.T) {

	testCases := []struct {
		name     string
		input    []byte
		expected EnterpriseDropNotify
		fail     bool
	}{
		{
			name: "v3extv1",
			input: []byte{0x0, 0x1, 0x3, 0x2,
				0x7, 0x6, 0x5, 0x4,
				0xb, 0xa, 0x9, 0x8,
				0x10, 0xe,
				0x3, 0x01, // version 3 ext 1
				0x14, 0x13, 0x12, 0x11,
				0x18, 0x17, 0x16, 0x15,
				0x1c, 0x1b, 0x1a, 0x19,
				0x1e, 0x1d,
				0x20,
				0x21,
				0x25, 0x24, 0x23, 0x22,
				0xf, 0x0, 0x0, 0x0,
				0x99, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
				0x39, 0x5, // SrcNetID
				0x2a, 0x0, // DstNetID
				0x0, 0x0, 0x0, 0x0},
			expected: EnterpriseDropNotify{
				DropNotify: DropNotify{
					Type:       0x00,
					SubType:    0x01,
					Source:     0x02_03,
					Hash:       0x04_05_06_07,
					OrigLen:    0x08_09_0a_0b,
					CapLen:     0x0e_10,
					Version:    0x03,
					ExtVersion: 0x01,
					SrcLabel:   0x11_12_13_14,
					DstLabel:   0x15_16_17_18,
					DstID:      0x19_1a_1b_1c,
					Line:       0x1d_1e,
					File:       0x20,
					ExtError:   0x21,
					Ifindex:    0x22_23_24_25,
					Flags:      0x0f,
					IPTraceID:  0x99,
				},
				SrcNetID: 1337,
				DstNetID: 42,
			},
		},
		{
			name: "v3extv1 - truncated",
			input: []byte{0x0, 0x1, 0x3, 0x2,
				0x7, 0x6, 0x5, 0x4,
				0xb, 0xa, 0x9, 0x8,
				0x10, 0xe,
				0x3, 0x01, // version 3 ext 1
				0x14, 0x13, 0x12, 0x11,
				0x18, 0x17, 0x16, 0x15,
				0x1c, 0x1b, 0x1a, 0x19,
				0x1e, 0x1d,
				0x20,
				0x21,
				0x25, 0x24, 0x23, 0x22,
				0xf, 0x0, 0x0, 0x0,
				0x99, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
				// Missing extension
			},
			expected: EnterpriseDropNotify{
				DropNotify: DropNotify{
					Type:       0x00,
					SubType:    0x01,
					Source:     0x02_03,
					Hash:       0x04_05_06_07,
					OrigLen:    0x08_09_0a_0b,
					CapLen:     0x0e_10,
					Version:    0x03,
					ExtVersion: 0x01,
					SrcLabel:   0x11_12_13_14,
					DstLabel:   0x15_16_17_18,
					DstID:      0x19_1a_1b_1c,
					Line:       0x1d_1e,
					File:       0x20,
					ExtError:   0x21,
					Ifindex:    0x22_23_24_25,
					Flags:      0x0f,
					IPTraceID:  0x99,
				},
			},
			fail: true,
		},
		{
			name: "v3noext -- don't parse rubbish",
			input: []byte{0x0, 0x1, 0x3, 0x2,
				0x7, 0x6, 0x5, 0x4,
				0xb, 0xa, 0x9, 0x8,
				0x10, 0xe,
				0x3, 0x00, // version 3 no extension
				0x14, 0x13, 0x12, 0x11,
				0x18, 0x17, 0x16, 0x15,
				0x1c, 0x1b, 0x1a, 0x19,
				0x1e, 0x1d,
				0x20,
				0x21,
				0x25, 0x24, 0x23, 0x22,
				0xf, 0x0, 0x0, 0x0,
				0x99, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
				// random data that should not be parsed
				0xde, 0xad,
				0xbe, 0xef,
				0x0, 0x0, 0x0, 0x0},
			expected: EnterpriseDropNotify{
				DropNotify: DropNotify{
					Type:       0x00,
					SubType:    0x01,
					Source:     0x02_03,
					Hash:       0x04_05_06_07,
					OrigLen:    0x08_09_0a_0b,
					CapLen:     0x0e_10,
					Version:    0x03,
					ExtVersion: 0x00,
					SrcLabel:   0x11_12_13_14,
					DstLabel:   0x15_16_17_18,
					DstID:      0x19_1a_1b_1c,
					Line:       0x1d_1e,
					File:       0x20,
					ExtError:   0x21,
					Ifindex:    0x22_23_24_25,
					Flags:      0x0f,
					IPTraceID:  0x99,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			output := EnterpriseDropNotify{}
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
