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
// crypto/fips140 module (Go 1.24+).
//
// To build with FIPS support:
//
//	GOFIPS140=v1.0.0 go build -tags fips ./...
//
// Or using make:
//
//	FIPS=1 make
//
// To run in FIPS mode:
//
//	GODEBUG=fips140=on ./cilium-agent
//
// For strict mode (non-FIPS algorithms return errors):
//
//	GODEBUG=fips140=only ./cilium-agent
//
// The crypto/fips140.Enabled() function can be used to check if FIPS mode
// is active at runtime.
//
// See https://go.dev/doc/security/fips140 for more details.

package fips
