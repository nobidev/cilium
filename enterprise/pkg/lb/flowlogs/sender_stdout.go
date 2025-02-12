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
		srcIP := net.IP(bytes[0:4])
		dstIP := net.IP(bytes[4:8])
		srcPort := binary.BigEndian.Uint16(bytes[8:10])
		dstPort := binary.BigEndian.Uint16(bytes[10:12])
		protocol := bytes[12]

		packetsTotal := flentry.Packets
		bytesTotal := flentry.Bytes

		r.logger.Info("Received flow log entry", "srcIP", srcIP, "srcPort", srcPort, "dstIP", dstIP, "dstPort", dstPort, "protocol", protocol, "packetsTotal", packetsTotal, "bytesTotal", bytesTotal)
	}

	return nil
}
