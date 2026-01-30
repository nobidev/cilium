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

func TestEnterprisePolicyVerdictNotify_Decode(t *testing.T) {

	testCases := []struct {
		name  string
		input EnterprisePolicyVerdictNotify
		fail  bool
	}{
		{
			name: "empty",
		},
		{
			name: "arbitrary",
			input: EnterprisePolicyVerdictNotify{
				PolicyVerdictNotify: PolicyVerdictNotify{
					Type:        0x00,
					SubType:     0x01,
					Source:      0x02_03,
					Hash:        0x04_05_06_07,
					OrigLen:     0x08_09_0a_0b,
					CapLen:      0x0c_0d,
					Version:     0x01,
					ExtVersion:  0x01,
					RemoteLabel: 0x11_12_13_14,
					Verdict:     0x15_16_17_18,
					DstPort:     0x19_1a,
					Proto:       0x1b,
					Flags:       0x1c,
					AuthType:    0x1d,
					Cookie:      0x1e_1f_20_21,
				},
				SrcNetID: 1337,
				DstNetID: 42,
			},
		},
		{
			name: "no extension version",
			input: EnterprisePolicyVerdictNotify{
				PolicyVerdictNotify: PolicyVerdictNotify{
					Type:        0x00,
					SubType:     0x01,
					Source:      0x02_03,
					Hash:        0x04_05_06_07,
					OrigLen:     0x08_09_0a_0b,
					CapLen:      0x0c_0d,
					Version:     0x01,
					ExtVersion:  0x00,
					RemoteLabel: 0x11_12_13_14,
					Verdict:     0x15_16_17_18,
					DstPort:     0x19_1a,
					Proto:       0x1b,
					Flags:       0x1c,
					AuthType:    0x1d,
					Cookie:      0x1e_1f_20_21,
				},
			},
		},
		{
			// We currently hard-code the single version in OSS
			// make sure we fail on a new version, as we'll need
			// to also update the enterprise code in that case.
			name: "unsupported version",
			input: EnterprisePolicyVerdictNotify{
				PolicyVerdictNotify: PolicyVerdictNotify{
					Type:        0x00,
					SubType:     0x01,
					Source:      0x02_03,
					Hash:        0x04_05_06_07,
					OrigLen:     0x08_09_0a_0b,
					CapLen:      0x0c_0d,
					Version:     0xfe,
					ExtVersion:  0x00,
					RemoteLabel: 0x11_12_13_14,
					Verdict:     0x15_16_17_18,
					DstPort:     0x19_1a,
					Proto:       0x1b,
					Flags:       0x1c,
					AuthType:    0x1d,
					Cookie:      0x1e_1f_20_21,
				},
			},
			fail: true,
		},
		{
			// to also update the enterprise code in that case.
			name: "unsupported extension version",
			input: EnterprisePolicyVerdictNotify{
				PolicyVerdictNotify: PolicyVerdictNotify{
					Type:        0x00,
					SubType:     0x01,
					Source:      0x02_03,
					Hash:        0x04_05_06_07,
					OrigLen:     0x08_09_0a_0b,
					CapLen:      0x0c_0d,
					Version:     0x01,
					ExtVersion:  0xfe,
					RemoteLabel: 0x11_12_13_14,
					Verdict:     0x15_16_17_18,
					DstPort:     0x19_1a,
					Proto:       0x1b,
					Flags:       0x1c,
					AuthType:    0x1d,
					Cookie:      0x1e_1f_20_21,
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

			output := EnterprisePolicyVerdictNotify{}
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

func TestEnterprisePolicyVerdictNotify_Decode_Raw(t *testing.T) {

	testCases := []struct {
		name     string
		input    []byte
		expected EnterprisePolicyVerdictNotify
		fail     bool
	}{
		{
			name: "arbitrary",
			input: []byte{
				0x00,
				0x01,
				0x03, 0x02,
				0x07, 0x06, 0x05, 0x04,
				0x0b, 0x0a, 0x09, 0x08,
				0x0d, 0x0c,
				0x01, // version 1
				0x01, // extension 1
				0x14, 0x13, 0x12, 0x11,
				0x18, 0x17, 0x16, 0x15,
				0x1a, 0x19,
				0x1b,
				0x1c,
				0x1d,
				0x0, 0x0, 0x0,
				0x21, 0x20, 0x1f, 0x1e,
				0x0, 0x0, 0x0, 0x0,
				0x39, 0x5, // SrcNetID
				0x2a, 0x0, // DstNetID
				0x0, 0x0, 0x0, 0x0,
			},
			expected: EnterprisePolicyVerdictNotify{
				PolicyVerdictNotify: PolicyVerdictNotify{
					Type:        0x00,
					SubType:     0x01,
					Source:      0x02_03,
					Hash:        0x04_05_06_07,
					OrigLen:     0x08_09_0a_0b,
					CapLen:      0x0c_0d,
					Version:     0x01,
					ExtVersion:  0x01,
					RemoteLabel: 0x11_12_13_14,
					Verdict:     0x15_16_17_18,
					DstPort:     0x19_1a,
					Proto:       0x1b,
					Flags:       0x1c,
					AuthType:    0x1d,
					Cookie:      0x1e_1f_20_21,
				},
				SrcNetID: 1337,
				DstNetID: 42,
			},
		},
		{
			name: "arbitrary trunc",
			input: []byte{
				0x00,
				0x01,
				0x03, 0x02,
				0x07, 0x06, 0x05, 0x04,
				0x0b, 0x0a, 0x09, 0x08,
				0x0d, 0x0c,
				0x01, // version 1
				0x01, // extension 1
				0x14, 0x13, 0x12, 0x11,
				0x18, 0x17, 0x16, 0x15,
				0x1a, 0x19,
				0x1b,
				0x1c,
				0x1d,
				0x0, 0x0, 0x0,
				0x21, 0x20, 0x1f, 0x1e,
				0x0, 0x0, 0x0, 0x0,
				// missing extension
			},
			expected: EnterprisePolicyVerdictNotify{
				PolicyVerdictNotify: PolicyVerdictNotify{
					Type:        0x00,
					SubType:     0x01,
					Source:      0x02_03,
					Hash:        0x04_05_06_07,
					OrigLen:     0x08_09_0a_0b,
					CapLen:      0x0c_0d,
					Version:     0x01,
					ExtVersion:  0x01,
					RemoteLabel: 0x11_12_13_14,
					Verdict:     0x15_16_17_18,
					DstPort:     0x19_1a,
					Proto:       0x1b,
					Flags:       0x1c,
					AuthType:    0x1d,
					Cookie:      0x1e_1f_20_21,
				},
			},
			fail: true,
		},
		{
			name: "arbitrary no ext -- don't parse rubbish",
			input: []byte{
				0x00,
				0x01,
				0x03, 0x02,
				0x07, 0x06, 0x05, 0x04,
				0x0b, 0x0a, 0x09, 0x08,
				0x0d, 0x0c,
				0x01, // version 1
				0x00, // no extension
				0x14, 0x13, 0x12, 0x11,
				0x18, 0x17, 0x16, 0x15,
				0x1a, 0x19,
				0x1b,
				0x1c,
				0x1d,
				0x0, 0x0, 0x0,
				0x21, 0x20, 0x1f, 0x1e,
				0x0, 0x0, 0x0, 0x0,
				// random data that should not be parsed
				0xde, 0xad,
				0xbe, 0xef,
				0x0, 0x0, 0x0, 0x0,
			},
			expected: EnterprisePolicyVerdictNotify{
				PolicyVerdictNotify: PolicyVerdictNotify{
					Type:        0x00,
					SubType:     0x01,
					Source:      0x02_03,
					Hash:        0x04_05_06_07,
					OrigLen:     0x08_09_0a_0b,
					CapLen:      0x0c_0d,
					Version:     0x01,
					ExtVersion:  0x00,
					RemoteLabel: 0x11_12_13_14,
					Verdict:     0x15_16_17_18,
					DstPort:     0x19_1a,
					Proto:       0x1b,
					Flags:       0x1c,
					AuthType:    0x1d,
					Cookie:      0x1e_1f_20_21,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			output := EnterprisePolicyVerdictNotify{}
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
