package main

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	"github.com/cilium/cilium/pkg/time"

	"google.golang.org/grpc"
)

// Each test should be ~fast, but time is a weird soup in CI.
var testTimeout = time.Second * 5

// These tests are less about testing the behaviour of our code, but instead
// codify some of the assumptions made about gRPC's behaviour. If these were to
// change, our code would become buggy which we should see as a test failure.

// Tests that connecting to a unix domain socket without a listener fails on
// first RPC ~instantaneously.
func TestConnectionFailureNoListener(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	socket := filepath.Join(t.TempDir(), "dnsproxy-test.socket")

	// Creating the client should succeed, since there's no connection attempt
	// at creation time.
	conn, err := createClient("unix:" + socket)
	if err != nil {
		t.Errorf("failed to create the client: %v", err)
	}
	// The first RPC establishes the conn, which should then fail
	// instantaneously, since there's no listener on the unix socket.
	_, err = pb.NewFQDNProxyAgentClient(conn).GetAllRules(ctx, &pb.Empty{})
	if err == nil {
		t.Errorf("gRPC call succeeded?!")
	}
}

// Tests that connecting to to a unix domain socket with a listener, but without
// a server to handle connections fails within reasonable time (currently 0.5s).
func TestConnectionFailureNoServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)

	startC := make(chan struct{})
	socket, err := startFakeServer(t, WithDelayStartUntil(startC))
	if err != nil {
		t.Fatalf("failed to setup the fake agent gRPC server: %v", err)
	}

	conn, err := createClient("unix:" + socket)
	if err != nil {
		t.Fatalf("failed to create the client: %v", err)
	}

	client := pb.NewFQDNProxyAgentClient(conn)

	// Total timeout of these two calls should be MinConnectionTimeout, ~500ms.
	// Give it some CI slack, but after all we're trying to test for "liveness"
	// here.
	sctx, cancel := context.WithTimeout(ctx, time.Second*2)
	t.Cleanup(cancel)

	// We want these to fail quickly if there's no connectivity to the agent,
	// and they should all fail within _one_ MinConnectionTimeout, not each wait
	// for a timeout.
	for i := range 10 {
		_, err = client.GetAllRules(sctx, &pb.Empty{})
		if err == nil {
			t.Errorf("%vth gRPC call succeeded when it should have failed", i)
		}
	}

	if sctx.Err() != nil {
		t.Errorf("context error before RPC calls completed: %v", ctx.Err())
	}

	// But once the server starts, there should be only a "small" delay.
	close(startC)

	// Once the server is up, account for a bit of time in backoff.
	tctx, cancel := context.WithTimeout(ctx, time.Millisecond*250)
	t.Cleanup(cancel)
	// Using wait for ready here to avoid retries and the race of waiting serving to start.
	_, err = client.GetAllRules(tctx, &pb.Empty{}, grpc.WaitForReady(true))
	if err != nil {
		t.Errorf("call should succeed after server started, but failed with: %v", err)
	}
}

func TestAgentCycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)

	stopC := make(chan struct{})
	socket, err := startFakeServer(t, WithStopServerOnClose(stopC))
	if err != nil {
		t.Fatalf("failed to setup the fake agent gRPC server: %v", err)
	}

	conn, err := createClient("unix:" + socket)
	if err != nil {
		t.Fatalf("failed to create the client: %v", err)
	}

	client := pb.NewFQDNProxyAgentClient(conn)

	_, err = client.GetAllRules(ctx, &pb.Empty{})
	if err != nil {
		t.Errorf("gRPC call failed before killing server: %v", err)
	}

	close(stopC)

	for ctx.Err() == nil {
		// Wait until socket is removed
		if f, err := os.Open(socket); errors.Is(err, fs.ErrNotExist) {
			break
		} else {
			f.Close()
		}
		time.Sleep(time.Millisecond * 50)
	}
	if ctx.Err() != nil {
		t.Fatalf("timed out waiting for socket removal: %v", ctx.Err())
	}

	for i := range 10 {
		_, err = client.GetAllRules(ctx, &pb.Empty{})
		if err == nil {
			t.Errorf("%vth gRPC call succeeded when it should have failed", i)
		}
	}

	// Need to make sure that the server listens on the same path as the old one.
	_, err = startFakeServer(t, WithFixedSocketPath(socket))
	if err != nil {
		t.Fatalf("failed to start new fake agent gRPC server: %v", err)
	}

	_, err = client.GetAllRules(ctx, &pb.Empty{}, grpc.WaitForReady(true))
	if err != nil {
		t.Errorf("gRPC call failed after server restart: %v", err)
	}
}

func startFakeServer(t *testing.T, opts ...fakeServerOpt) (string, error) {
	t.Helper()

	fakeImpl := &fakeAgent{
		socketPath: filepath.Join(t.TempDir(), "dnsproxy-test.socket"),
	}
	for _, o := range opts {
		o(fakeImpl)
	}
	grpcServer := grpc.NewServer()
	pb.RegisterFQDNProxyAgentServer(grpcServer, fakeImpl)

	lis, err := net.Listen("unix", fakeImpl.socketPath)
	if err != nil {
		t.Errorf("failed to listen: %v", err)
		return "", err
	}
	t.Cleanup(func() {
		grpcServer.Stop()
		lis.Close()
		os.Remove(fakeImpl.socketPath)
	})

	go func() {
		if fakeImpl.startServerOn != nil {
			<-fakeImpl.startServerOn
		}
		err = grpcServer.Serve(lis)
		if err != nil {
			t.Logf("Server stopped with err %v", err)
		}
	}()

	if fakeImpl.stopServerOn != nil {
		go func() {
			<-fakeImpl.stopServerOn
			grpcServer.Stop()
			lis.Close()
			os.Remove(fakeImpl.socketPath)
		}()
	}

	return fakeImpl.socketPath, nil
}

type fakeServerOpt func(*fakeAgent)

func WithDelayStartUntil(c chan struct{}) fakeServerOpt {
	return func(fa *fakeAgent) {
		fa.startServerOn = c
	}
}

func WithStopServerOnClose(c chan struct{}) fakeServerOpt {
	return func(fa *fakeAgent) {
		fa.stopServerOn = c
	}
}

func WithFixedSocketPath(p string) fakeServerOpt {
	return func(fa *fakeAgent) {
		fa.socketPath = p
	}
}

type fakeAgent struct {
	pb.UnimplementedFQDNProxyAgentServer

	startServerOn chan struct{}
	stopServerOn  chan struct{}

	socketPath string
}

func (*fakeAgent) GetAllRules(context.Context, *pb.Empty) (*pb.RestoredRulesMap, error) {
	return &pb.RestoredRulesMap{}, nil
}
