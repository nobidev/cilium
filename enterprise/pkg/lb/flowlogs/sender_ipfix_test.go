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
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/vmware/go-ipfix/pkg/exporter"
)

func TestSendWithFallbackEmptyList(t *testing.T) {
	sender := &flowLogIPFixSender{
		logger:            slog.New(slog.DiscardHandler),
		collectorProtocol: "tcp",
	}

	err := sender.sendWithFallback(func(*exporter.ExportingProcess) error { return nil })
	if err == nil {
		t.Fatalf("expected error for empty collector list")
	}
}

func TestSendWithFallbackFirstSuccess(t *testing.T) {
	addr, stop := startTestTCPListener(t)
	defer stop()

	sender := &flowLogIPFixSender{
		logger:             slog.New(slog.DiscardHandler),
		collectorAddresses: []string{addr},
		collectorProtocol:  "tcp",
	}

	calls := 0
	err := sender.sendWithFallback(func(*exporter.ExportingProcess) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 send attempt, got %d", calls)
	}
}

func TestSendWithFallbackFailoverOnSendError(t *testing.T) {
	addr1, stop1 := startTestTCPListener(t)
	defer stop1()
	addr2, stop2 := startTestTCPListener(t)
	defer stop2()

	sender := &flowLogIPFixSender{
		logger:             slog.New(slog.DiscardHandler),
		collectorAddresses: []string{addr1, addr2},
		collectorProtocol:  "tcp",
	}

	calls := 0
	err := sender.sendWithFallback(func(*exporter.ExportingProcess) error {
		calls++
		if calls == 1 {
			return fmt.Errorf("boom")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 send attempts, got %d", calls)
	}
}

func TestSendWithFallbackFailoverOnConnectError(t *testing.T) {
	addr, stop := startTestTCPListener(t)
	defer stop()

	sender := &flowLogIPFixSender{
		logger:             slog.New(slog.DiscardHandler),
		collectorAddresses: []string{"127.0.0.1:0", addr},
		collectorProtocol:  "tcp",
	}

	calls := 0
	err := sender.sendWithFallback(func(*exporter.ExportingProcess) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 send attempt after connect failover, got %d", calls)
	}
}

func TestSendWithFallbackAllCollectorsFail(t *testing.T) {
	addr1, stop1 := startTestTCPListener(t)
	defer stop1()
	addr2, stop2 := startTestTCPListener(t)
	defer stop2()

	sender := &flowLogIPFixSender{
		logger:             slog.New(slog.DiscardHandler),
		collectorAddresses: []string{addr1, addr2},
		collectorProtocol:  "tcp",
	}

	calls := 0
	err := sender.sendWithFallback(func(*exporter.ExportingProcess) error {
		calls++
		return fmt.Errorf("boom")
	})
	if err == nil {
		t.Fatalf("expected error when all collectors fail")
	}
	if calls != 2 {
		t.Fatalf("expected send attempts to all collectors, got %d", calls)
	}
	if !strings.Contains(err.Error(), "failed to send flow logs to any IPFix collector") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func startTestTCPListener(t *testing.T) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				_, _ = io.Copy(io.Discard, c)
				_ = c.Close()
			}(conn)
		}
	}()

	return ln.Addr().String(), func() {
		close(done)
		_ = ln.Close()
	}
}
