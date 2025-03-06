//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lbflowlogs

import (
	"encoding/binary"

	"github.com/cilium/cilium/pkg/logging/logfields"

	"log/slog"
	"net"
)

var _ FlowLogSender = &flowLogStdoutSender{}

// flowLogStdoutSender is a flow log sender that prints
// received flow log entries to stdout for debugging purposes.
type flowLogStdoutSender struct {
	logger *slog.Logger
}

func newFlowLogStdoutSender(logger *slog.Logger) lbFlowLogSenderOut {
	sender := &flowLogStdoutSender{
		logger: logger,
	}

	return lbFlowLogSenderOut{Sender: sender}
}

func (r *flowLogStdoutSender) Name() string {
	return "stdout"
}

func (r *flowLogStdoutSender) SendFlowLogs(flowLogs FlowLogTable) error {
	for flkey, flentry := range flowLogs {
		bytes := []byte(flkey)
		ifindex := int(binary.NativeEndian.Uint32(bytes[ifindexStart : ifindexStart+ifindexSize]))
		srcIP := net.IP(bytes[saddrStart : saddrStart+saddrSize])
		dstIP := net.IP(bytes[daddrStart : daddrStart+daddrSize])
		srcPort := binary.BigEndian.Uint16(bytes[sportStart : sportStart+sportSize])
		dstPort := binary.BigEndian.Uint16(bytes[dportStart : dportStart+dportSize])
		protocol := bytes[nexthdrStart]

		packetsTotal := flentry.Packets
		bytesTotal := flentry.Bytes

		ifName, err := InterfaceByIndex(ifindex)
		if err != nil {
			r.logger.Error("InterfaceByIndex", logfields.Error, err, "ifindex", ifindex)
			ifName = "<unknown>"
		}

		r.logger.Info("Received flow log entry", "interface", ifName, "srcIP", srcIP, "srcPort", srcPort, "dstIP", dstIP, "dstPort", dstPort, "protocol", protocol, "packetsTotal", packetsTotal, "bytesTotal", bytesTotal)
	}

	return nil
}
