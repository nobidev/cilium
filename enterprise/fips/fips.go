//go:build fips

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

// Package fips enables FIPS 140-3 compliant cryptography using Go's native
// crypto/fips140 module (Go 1.24+). This replaces the previous BoringCrypto
// implementation.
//
// To enable FIPS mode:
//   - Build with: GOFIPS140=v1.0.0 go build -tags fips
//   - Run with: GODEBUG=fips140=on ./binary
//
// See https://go.dev/doc/security/fips140 for details.
package fips

import (
	"crypto/fips140"
	"crypto/tls"
	"log"

	"github.com/cilium/cilium/pkg/hubble/relay/server"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
)

func init() {
	// Native Go FIPS 140-3 mode (Go 1.24+) supports TLS 1.3, unlike BoringCrypto
	// which was limited to TLS 1.2. However, we still set TLS 1.2 as minimum
	// for broad compatibility.
	//
	// FIPS mode is controlled at runtime via GODEBUG=fips140=on (or =only).
	// When enabled, crypto/tls automatically restricts to FIPS-approved
	// cipher suites and algorithms.
	//
	// See: https://go.dev/doc/security/fips140
	server.MinTLSVersion = tls.VersionTLS12
	serveroption.MinTLSVersion = tls.VersionTLS12

	if fips140.Enabled() {
		log.Println("FIPS 140-3 mode is enabled")
	}
}
