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
	"github.com/cilium/cilium/pkg/logging/logfields"

	"net"

	"log/slog"
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

func (r *flowLogStdoutSender) SendFlowLogs(flowLogsV4 FlowLogTableV4, flowLogsV6 FlowLogTableV6, flowLogsL2 FlowLogTableL2) error {

	for flkey, flentry := range flowLogsV4 {
		ifName, err := InterfaceByIndex(int(flkey.Ifindex))
		if err != nil {
			r.logger.Error("InterfaceByIndex",
				logfields.Error, err,
				logfields.LinkIndex, flkey.Ifindex)
			ifName = "<unknown>"
		}
		r.logger.Info("Received v4 flow log entry",
			logfields.Interface, ifName,
			logfields.SrcIP, uint32ToIP(flkey.SrcAddr),
			logfields.SrcPort, ntohs(flkey.SrcPort),
			logfields.DstIP, uint32ToIP(flkey.DstAddr),
			logfields.DstPort, ntohs(flkey.DstPort),
			logfields.Protocol, flkey.Nexthdr,
			logfields.PacketsTotal, flentry.Packets,
			logfields.BytesTotal, flentry.Bytes,
			logfields.StartTime, flentry.firstTs,
			logfields.EndTime, flentry.ts,
		)
	}

	for flkey, flentry := range flowLogsV6 {
		ifName, err := InterfaceByIndex(int(flkey.Ifindex))
		if err != nil {
			r.logger.Error("InterfaceByIndex",
				logfields.Error, err,
				logfields.LinkIndex, flkey.Ifindex)
			ifName = "<unknown>"
		}
		r.logger.Info("Received v6 flow log entry",
			logfields.Interface, ifName,
			logfields.SrcIP, net.IP(flkey.SrcAddr[:]),
			logfields.SrcPort, ntohs(flkey.SrcPort),
			logfields.DstIP, net.IP(flkey.DstAddr[:]),
			logfields.DstPort, ntohs(flkey.DstPort),
			logfields.Protocol, flkey.Nexthdr,
			logfields.PacketsTotal, flentry.Packets,
			logfields.BytesTotal, flentry.Bytes,
			logfields.StartTime, flentry.firstTs,
			logfields.EndTime, flentry.ts,
		)
	}

	for flkey, flentry := range flowLogsL2 {
		ifName, err := InterfaceByIndex(int(flkey.Ifindex))
		if err != nil {
			r.logger.Error("InterfaceByIndex",
				logfields.Error, err,
				logfields.LinkIndex, flkey.Ifindex)
			ifName = "<unknown>"
		}
		r.logger.Info("Received L2 flow log entry",
			logfields.Interface, ifName,
			logfields.MACAddr, net.HardwareAddr(flkey.SrcMac[:]),
			logfields.MACAddr, net.HardwareAddr(flkey.DstMac[:]),
			logfields.Protocol, ntohs(flkey.Type),
			logfields.PacketsTotal, flentry.Packets,
			logfields.BytesTotal, flentry.Bytes,
			logfields.StartTime, flentry.firstTs,
			logfields.EndTime, flentry.ts,
		)
	}

	return nil
}
