// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package healthchecker

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestProbe(t *testing.T) {
	t.Cleanup(func() { testutils.GoleakVerifyNone(t) })

	const (
		testHTTPHost      = "test.cilium.io"
		validHTTPPath     = "/success"
		checkHostHTTPPath = "/check-host"
	)

	table := []struct {
		name              string            // name of the test case
		config            HealthCheckConfig // service health-check config
		overrideProbePort bool              // true if probe port must be used instead of service port
		useHTTPSServer    bool              // true if the probe will be connecting to the HTTPS server
		useInvalidServer  bool              // true if the probe will be connecting to an invalid server
		expectHealthy     bool              // true if healthy probe result is expected
	}{
		{
			name: "test simple HTTP probe",
			config: HealthCheckConfig{
				L7: true,
			},
			expectHealthy: true,
		},
		{
			name: "test simple HTTPS probe",
			config: HealthCheckConfig{
				L7:         true,
				HTTPScheme: HealthCheckSchemeHTTPS,
			},
			useHTTPSServer: true,
			expectHealthy:  true,
		},
		{
			name: "test simple HTTP probe to invalid server",
			config: HealthCheckConfig{
				L7:           true,
				ProbeTimeout: 100 * time.Millisecond,
			},
			useInvalidServer: true,
			expectHealthy:    false,
		},
		{
			name: "test HTTPS probe to HTTP-only server",
			config: HealthCheckConfig{
				L7:         true,
				HTTPScheme: HealthCheckSchemeHTTPS,
			},
			useHTTPSServer: false,
			expectHealthy:  false,
		},
		{
			name: "test HTTP probe to HTTPS-only server",
			config: HealthCheckConfig{
				L7: true,
			},
			useHTTPSServer: true,
			expectHealthy:  false,
		},
		{
			name: "test valid HTTP path",
			config: HealthCheckConfig{
				L7:       true,
				HTTPPath: validHTTPPath,
			},
			expectHealthy: true,
		},
		{
			name: "test valid HTTPS path",
			config: HealthCheckConfig{
				L7:         true,
				HTTPScheme: HealthCheckSchemeHTTPS,
				HTTPPath:   validHTTPPath,
			},
			useHTTPSServer: true,
			expectHealthy:  true,
		},
		{
			name: "test invalid HTTP path",
			config: HealthCheckConfig{
				L7:       true,
				HTTPPath: "/invalid",
			},
			expectHealthy: false,
		},
		{
			name: "test invalid HTTPS path",
			config: HealthCheckConfig{
				L7:         true,
				HTTPScheme: HealthCheckSchemeHTTPS,
				HTTPPath:   "/invalid",
			},
			useHTTPSServer: true,
			expectHealthy:  false,
		},
		{
			name: "test valid HTTP host",
			config: HealthCheckConfig{
				L7:       true,
				HTTPPath: "/check-host",
				HTTPHost: testHTTPHost,
			},
			expectHealthy: true,
		},
		{
			name: "test valid HTTPS host",
			config: HealthCheckConfig{
				L7:         true,
				HTTPScheme: HealthCheckSchemeHTTPS,
				HTTPPath:   checkHostHTTPPath,
				HTTPHost:   testHTTPHost,
			},
			useHTTPSServer: true,
			expectHealthy:  true,
		},
		{
			name: "test invalid HTTP host",
			config: HealthCheckConfig{
				L7:       true,
				HTTPPath: checkHostHTTPPath,
				HTTPHost: "invalid.host.io",
			},
			expectHealthy: false,
		},
		{
			name: "test invalid HTTPS host",
			config: HealthCheckConfig{
				L7:         true,
				HTTPScheme: HealthCheckSchemeHTTPS,
				HTTPPath:   checkHostHTTPPath,
				HTTPHost:   "invalid.host.io",
			},
			useHTTPSServer: true,
			expectHealthy:  false,
		},
		{
			name: "test simple HEAD method",
			config: HealthCheckConfig{
				L7:         true,
				HTTPMethod: HealthCheckMethodHead,
			},
			expectHealthy: true,
		},
		{
			name: "test HTTPS HEAD method",
			config: HealthCheckConfig{
				L7:         true,
				HTTPScheme: HealthCheckSchemeHTTPS,
				HTTPMethod: HealthCheckMethodHead,
			},
			useHTTPSServer: true,
			expectHealthy:  true,
		},
		{
			name: "test HEAD method with invalid HTTP path",
			config: HealthCheckConfig{
				L7:         true,
				HTTPMethod: HealthCheckMethodHead,
				HTTPPath:   "/invalid",
			},
			expectHealthy: false,
		},
		{
			name: "test probe port override",
			config: HealthCheckConfig{
				L7: true,
			},
			overrideProbePort: true,
			expectHealthy:     true,
		},
	}

	// request handler used for both HTTP and HTTPS servers
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.RequestURI {
		case "/":
		case validHTTPPath:
			w.WriteHeader(http.StatusOK)
		case checkHostHTTPPath:
			// returns internal error if HTTP host / TLS Server Name does not match the expected value
			fail := false
			if r.Host != testHTTPHost {
				fail = true
			}
			if r.TLS != nil {
				if r.TLS.ServerName != testHTTPHost {
					fail = true
				}
			}
			if fail {
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	httpServer := httptest.NewServer(testHandler)
	defer httpServer.Close()
	httpAddr := getTestServerL3n4Addr(t, httpServer.Listener.Addr())

	httpsServer := httptest.NewTLSServer(testHandler)
	defer httpsServer.Close()
	httpsAddr := getTestServerL3n4Addr(t, httpsServer.Listener.Addr())

	dummyTCPListener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dummyTCPListener.Close()
	dummyAddr := getTestServerL3n4Addr(t, dummyTCPListener.Addr())
	// Accept and immediately close connections so probes hitting the dummy port fail reliably.
	go func() {
		for {
			conn, err := dummyTCPListener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	logger := slog.New(slog.DiscardHandler)
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// send the probe
			probeAddr := httpAddr
			if tt.useHTTPSServer {
				probeAddr = httpsAddr
			}
			if tt.useInvalidServer {
				probeAddr = dummyAddr
			}
			params := probeParams{
				ctx:     context.TODO(),
				logger:  logger,
				config:  tt.config,
				svcAddr: probeAddr,
				beAddr:  probeAddr,
			}
			if tt.overrideProbePort {
				params.svcAddr = dummyAddr
				params.beAddr = dummyAddr
				params.config.ProbePort = httpAddr.Port()
			}
			res := probe(params)

			// check the result
			if res.healthy != tt.expectHealthy {
				t.Fatalf("non-expected probe result: %v (%s)", res.healthy, res.message)
			}
		})
	}
}

func TestProbePortOverrideSNAT(t *testing.T) {
	t.Cleanup(func() { testutils.GoleakVerifyNone(t) })

	oldEnableHealthDatapath := option.Config.EnableHealthDatapath
	// Forces SNAT path by setting option.Config.EnableHealthDatapath = false
	option.Config.EnableHealthDatapath = false
	t.Cleanup(func() { option.Config.EnableHealthDatapath = oldEnableHealthDatapath })

	successListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer successListener.Close()
	successAddr := getTestServerL3n4Addr(t, successListener.Addr())

	closedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := getTestServerL3n4Addr(t, closedListener.Addr())
	closedListener.Close()

	logger := slog.New(slog.DiscardHandler)
	baseParams := probeParams{
		ctx:    context.TODO(),
		logger: logger,
		config: HealthCheckConfig{
			DSR:          true,
			ProbeTimeout: 200 * time.Millisecond,
		},
		svcAddr: closedAddr,
		beAddr:  closedAddr,
	}

	res := probe(baseParams)
	if res.healthy {
		t.Fatalf("expected probe to fail without override, got healthy")
	}

	baseParams.config.ProbePort = successAddr.Port()
	res = probe(baseParams)
	if !res.healthy {
		t.Fatalf("expected probe to succeed with override, got unhealthy (%s)", res.message)
	}
}

func TestAddrWithProbePort(t *testing.T) {
	t.Cleanup(func() { testutils.GoleakVerifyNone(t) })

	baseAddr := lb.NewL3n4Addr(
		lb.TCP,
		cmtypes.MustParseAddrCluster("10.0.0.2"),
		80,
		lb.ScopeExternal,
	)

	tests := []struct {
		name     string
		config   HealthCheckConfig
		wantPort uint16
	}{
		{
			name:     "probe port unset",
			config:   HealthCheckConfig{ProbePort: 0},
			wantPort: 80,
		},
		{
			name:     "probe port matches",
			config:   HealthCheckConfig{ProbePort: 80},
			wantPort: 80,
		},
		{
			name:     "probe port overrides",
			config:   HealthCheckConfig{ProbePort: 81},
			wantPort: 81,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := probeParams{config: tt.config}
			got := p.addrWithProbePort(baseAddr)
			if got.Port() != tt.wantPort {
				t.Fatalf("addrWithProbePort() port = %d, want %d", got.Port(), tt.wantPort)
			}
			if got.Protocol() != baseAddr.Protocol() {
				t.Fatalf("addrWithProbePort() protocol = %v, want %v", got.Protocol(), baseAddr.Protocol())
			}
			if got.AddrCluster().String() != baseAddr.AddrCluster().String() {
				t.Fatalf("addrWithProbePort() addr = %v, want %v", got.AddrCluster(), baseAddr.AddrCluster())
			}
			if got.Scope() != baseAddr.Scope() {
				t.Fatalf("addrWithProbePort() scope = %v, want %v", got.Scope(), baseAddr.Scope())
			}
		})
	}
}

func getTestServerL3n4Addr(t *testing.T, addr net.Addr) lb.L3n4Addr {
	addrParts := strings.Split(addr.String(), ":")
	if len(addrParts) != 2 {
		t.Fatalf("could not split server address %s (%v)", addr.String(), addrParts)
	}
	port, err := strconv.ParseUint(addrParts[1], 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return lb.NewL3n4Addr(lb.TCP, cmtypes.MustParseAddrCluster(addrParts[0]), uint16(port), lb.ScopeExternal)
}
