// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package timescape

import (
	"context"
	"crypto/tls"
	"net"

	"google.golang.org/grpc/credentials"

	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/lock"
)

// minTLSVersion defines the minimum TLS version that is acceptable for connecting to a remote
// server.
const minTLSVersion uint16 = tls.VersionTLS13

// TODO: This file is a copy of the grpcTLSCredentialsWrapper from
// pkg/hubble/relay/pool/client.go. We should move it to a common package
// that can be imported by both the hubble/relay and hubble/export packages.
//
// grpcTLSCredentialsWrapper wraps gRPC TransportCredentials and fetches the
// newest TLS configuration from certloader whenever a new TLS connection
// is established.
//
// A gRPC ClientConn will call ClientHandshake whenever it tries to establish
// a new TLS connection.
//
// Wrapping the ClientHandshake and fetching the updated certificate and CA
// allows us to transparently reload certificates when they change.
type grpcTLSCredentialsWrapper struct {
	credentials.TransportCredentials

	mu        lock.Mutex
	baseConf  *tls.Config
	TLSConfig certloader.ClientConfigBuilder
}

// ClientHandshake implements credentials.TransportCredentials.
func (w *grpcTLSCredentialsWrapper) ClientHandshake(ctx context.Context, addr string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.TransportCredentials = credentials.NewTLS(w.TLSConfig.ClientConfig(w.baseConf))
	return w.TransportCredentials.ClientHandshake(ctx, addr, conn)
}

// Clone implements credentials.TransportCredentials.
func (w *grpcTLSCredentialsWrapper) Clone() credentials.TransportCredentials {
	w.mu.Lock()
	defer w.mu.Unlock()
	return &grpcTLSCredentialsWrapper{
		baseConf:             w.baseConf.Clone(),
		TransportCredentials: w.TransportCredentials.Clone(),
		TLSConfig:            w.TLSConfig,
	}
}
