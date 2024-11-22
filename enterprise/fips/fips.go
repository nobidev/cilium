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

package fips

import (
	"crypto/tls"
	_ "crypto/tls/fipsonly"

	"github.com/cilium/cilium/pkg/hubble/relay/server"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
)

func init() {
	// As of 2024/11/22, boringcrypto only supports `tls.Config.MinVersion == TLS1.2`. An issue in the
	// Go repository details the work toward allowing more recent FIPS-approved protocols/algorithms
	// (including TLS 1.3) but was closed because of missing algorithm in the latest version of
	// BoringCrypto.
	// https://github.com/golang/go/issues/62372
	//
	// An issue was opened in the Go repository on 2024/09/19 to add a FIPS 140-3 compliant package in
	// the standard library targeted for Go 1.24.
	// https://github.com/golang/go/issues/69536
	server.MinTLSVersion = tls.VersionTLS12
	serveroption.MinTLSVersion = tls.VersionTLS12
}
