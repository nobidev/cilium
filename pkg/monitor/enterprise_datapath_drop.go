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
	DropNotifyExtensionV1Len = 8 // bytes
)

const (
	DropNotifyExtensionV1 = iota + 1
)

func init() {
	dropNotifyExtensionLengthFromVersion[DropNotifyExtensionV1] = DropNotifyExtensionV1Len
}

type EnterpriseDropNotify struct {
	DropNotify
	SrcNetID uint16
	DstNetID uint16
	Pad      uint32
}

func (n *EnterpriseDropNotify) Decode(data []byte) error {
	if err := (&n.DropNotify).Decode(data); err != nil {
		return err
	}

	base := dropNotifyLengthFromVersion[n.Version]
	switch n.ExtVersion {
	case DropNotifyExtensionV1:
		if l := uint(len(data)); l < base+DropNotifyExtensionV1Len {
			return fmt.Errorf("unexpected DropNotify extension data length, expected at least %d but got %d", base+DropNotifyExtensionV1Len, l)
		}
		srcStart := base
		dstStart := base + 2
		end := base + 4
		n.SrcNetID = binary.NativeEndian.Uint16(data[srcStart:dstStart])
		n.DstNetID = binary.NativeEndian.Uint16(data[dstStart:end])
	case DropNotifyExtensionDisabled:
	default:
		return fmt.Errorf("unrecognized drop extension (version %d)", n.ExtVersion)
	}

	return nil
}
