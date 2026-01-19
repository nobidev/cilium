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
	"encoding/binary"
	"fmt"
)

const (
	PolicyVerdictNotifyExtensionV1Len = 8 // bytes
)

const (
	PolicyVerdictNotifyExtensionV1 = iota + 1
)

func init() {
	policyVerdictExtensionLengthFromVersion[PolicyVerdictNotifyExtensionV1] = PolicyVerdictNotifyExtensionV1Len
}

type EnterprisePolicyVerdictNotify struct {
	PolicyVerdictNotify
	SrcNetID uint16
	DstNetID uint16
	Pad      uint32
}

func (n *EnterprisePolicyVerdictNotify) Decode(data []byte) error {
	if err := (&n.PolicyVerdictNotify).Decode(data); err != nil {
		return err
	}

	if n.Version > 1 {
		// OSS currently only supports a single version and if OSS ever adds a new version, we'll break.
		// Depending on the change, the breakage might even be silent, so let's double check here and
		// fail if we encounter a newer version.
		return fmt.Errorf("unrecognized policy verdict event (version %d). Likely indicates a programming error. PolicyVerdictNotify extension code needs to be updated", n.Verdict)
	}

	base := PolicyVerdictNotifyLen
	switch n.ExtVersion {
	case PolicyVerdictNotifyExtensionV1:
		if l := len(data); l < base+PolicyVerdictNotifyExtensionV1Len {
			return fmt.Errorf("unexpected PolicyVerdictNotify extension data length, expected at least %d but got %d", base+PolicyVerdictNotifyExtensionV1Len, l)
		}
		srcStart := base
		dstStart := base + 2
		end := base + 4
		n.SrcNetID = binary.NativeEndian.Uint16(data[srcStart:dstStart])
		n.DstNetID = binary.NativeEndian.Uint16(data[dstStart:end])
	case PolicyVerdictExtensionDisabled:
	default:
		return fmt.Errorf("unrecognized policy verdict notify extension (version %d)", n.ExtVersion)
	}

	return nil
}
