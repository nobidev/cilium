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
	"log/slog"
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/time"
)

func TestBandwidth2Str(t *testing.T) {
	if got := bandwidth2Str(0, time.Second); got != "0.00 Kb/s" {
		t.Fatalf("expected 0.00 Kb/s, got %q", got)
	}
	if got := bandwidth2Str(1024, time.Second); got != "1.00 Kb/s" {
		t.Fatalf("expected 1.00 Kb/s, got %q", got)
	}
	if got := bandwidth2Str(1024*1024, time.Second); got != "1.00 Mb/s" {
		t.Fatalf("expected 1.00 Mb/s, got %q", got)
	}
}

func TestMergeFlowLogsV4(t *testing.T) {
	processor := &flowLogProcessor{
		logger:          slog.New(slog.DiscardHandler),
		reportFrequency: 10 * time.Second,
	}

	keyExisting := FlowLogKeyV4{
		Ifindex: 1,
		SrcAddr: 1,
		DstAddr: 2,
		SrcPort: 80,
		DstPort: 443,
		Nexthdr: 6,
	}
	keyNew := FlowLogKeyV4{
		Ifindex: 2,
		SrcAddr: 3,
		DstAddr: 4,
		SrcPort: 53,
		DstPort: 53,
		Nexthdr: 17,
	}

	firstTs := time.Unix(50, 0)
	all := FlowLogTableV4{
		keyExisting: {
			Packets: 2,
			Bytes:   100,
			ts:      time.Unix(90, 0),
			firstTs: firstTs,
		},
	}
	newFlowLogs := FlowLogTableV4{
		keyExisting: {
			Packets: 3,
			Bytes:   60,
			ts:      time.Unix(100, 0),
			firstTs: time.Unix(80, 0),
		},
		keyNew: {
			Packets: 1,
			Bytes:   10,
			ts:      time.Unix(101, 0),
			firstTs: time.Unix(101, 0),
		},
	}

	processor.mergeFlowLogsV4(newFlowLogs, all, time.Unix(110, 0))

	got := all[keyExisting]
	if got.Packets != 5 || got.Bytes != 160 {
		t.Fatalf("unexpected aggregated values: packets=%d bytes=%d", got.Packets, got.Bytes)
	}
	if !got.firstTs.Equal(firstTs) {
		t.Fatalf("expected firstTs to be preserved, got %v", got.firstTs)
	}
	if !got.ts.Equal(newFlowLogs[keyExisting].ts) {
		t.Fatalf("expected ts to be updated to latest, got %v", got.ts)
	}

	gotNew := all[keyNew]
	if !gotNew.firstTs.Equal(newFlowLogs[keyNew].firstTs) {
		t.Fatalf("expected firstTs to be set for new key, got %v", gotNew.firstTs)
	}
}

func TestCleanupFlowLogsV4(t *testing.T) {
	processor := &flowLogProcessor{logger: slog.New(slog.DiscardHandler)}

	keyOld := FlowLogKeyV4{Ifindex: 0}
	keyNew := FlowLogKeyV4{Ifindex: 1}

	big := FlowLogTableV4{
		keyOld: {ts: time.Unix(10, 0)},
		keyNew: {ts: time.Unix(20, 0)},
	}

	processor.cleanupFlowLogsV4(big, time.Unix(15, 0))
	if len(big) != 1 {
		t.Fatalf("expected 1 entry after cleanup, got %d", len(big))
	}
	if _, ok := big[keyNew]; !ok {
		t.Fatalf("expected newer entry to remain after cleanup")
	}
}

func TestCleanupFlowLogsL2(t *testing.T) {
	processor := &flowLogProcessor{logger: slog.New(slog.DiscardHandler)}

	keyOld := FlowLogKeyL2{Ifindex: 0}
	keyNew := FlowLogKeyL2{Ifindex: 1}

	big := FlowLogTableL2{
		keyOld: {ts: time.Unix(10, 0)},
		keyNew: {ts: time.Unix(20, 0)},
	}

	processor.cleanupFlowLogsL2(big, time.Unix(15, 0))
	if len(big) != 1 {
		t.Fatalf("expected 1 entry after cleanup, got %d", len(big))
	}
	if _, ok := big[keyNew]; !ok {
		t.Fatalf("expected newer entry to remain after cleanup")
	}
}

func TestFlowLogRecordKeyToString(t *testing.T) {
	processor := &flowLogProcessor{logger: slog.New(slog.DiscardHandler)}

	keyV4 := FlowLogKeyV4{Ifindex: 0, SrcAddr: 1, DstAddr: 2, SrcPort: 80, DstPort: 443, Nexthdr: 6}
	v4 := processor.flowLogRecordKeyToStringV4(keyV4)
	if !strings.Contains(v4, "<unknown>") || !strings.Contains(v4, "00000001:80") || !strings.Contains(v4, "[tcp]") {
		t.Fatalf("unexpected V4 key string: %q", v4)
	}

	var srcV6 [16]uint8
	srcV6[15] = 1
	var dstV6 [16]uint8
	dstV6[15] = 2
	keyV6 := FlowLogKeyV6{Ifindex: 0, SrcAddr: srcV6, DstAddr: dstV6, SrcPort: 123, DstPort: 456, Nexthdr: 17}
	v6 := processor.flowLogRecordKeyToStringV6(keyV6)
	if !strings.Contains(v6, "<unknown>") || !strings.Contains(v6, "::1:123") || !strings.Contains(v6, "[udp]") {
		t.Fatalf("unexpected V6 key string: %q", v6)
	}

	keyL2 := FlowLogKeyL2{
		Ifindex: 0,
		SrcMac:  [6]uint8{1, 2, 3, 4, 5, 6},
		DstMac:  [6]uint8{10, 11, 12, 13, 14, 15},
		Type:    0x0800,
	}
	l2 := processor.flowLogRecordKeyToStringL2(keyL2)
	if !strings.Contains(l2, "<unknown>") || !strings.Contains(l2, "ethertype=0800") {
		t.Fatalf("unexpected L2 key string: %q", l2)
	}
}
