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
	TraceNotifyExtensionV1Len = 8 // bytes
)

const (
	TraceNotifyExtensionV1 = iota + 1
)

func init() {
	traceNotifyExtensionLengthFromVersion[TraceNotifyExtensionV1] = TraceNotifyExtensionV1Len
}

type EnterpriseTraceNotify struct {
	TraceNotify
	SrcNetID uint16
	DstNetID uint16
	Pad      uint32
}

func (n *EnterpriseTraceNotify) Decode(data []byte) error {
	if err := (&n.TraceNotify).Decode(data); err != nil {
		return err
	}

	base := traceNotifyLength[n.Version]
	switch n.ExtVersion {
	case TraceNotifyExtensionV1:
		if l := uint(len(data)); l < base+TraceNotifyExtensionV1Len {
			return fmt.Errorf("unexpected TraceNotify extension data length, expected at least %d but got %d", base+TraceNotifyExtensionV1Len, l)
		}
		srcStart := base
		dstStart := base + 2
		end := base + 4
		n.SrcNetID = binary.NativeEndian.Uint16(data[srcStart:dstStart])
		n.DstNetID = binary.NativeEndian.Uint16(data[dstStart:end])
	case DropNotifyExtensionDisabled:
	default:
		return fmt.Errorf("unrecognized notify extension (version %d)", n.ExtVersion)
	}

	return nil
}
