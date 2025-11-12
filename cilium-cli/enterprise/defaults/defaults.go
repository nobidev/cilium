//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package defaults

import "time"

const (
	// EgressGatewayConnectRetryDefault is the default number of retries on connection failure for EGW IPAM tests
	EgressGatewayConnectRetryDefault = 5
	// EgressGatewayConnectRetryDelayDefault is the default delay between retries on connection failure for EGW IPAM tests
	EgressGatewayConnectRetryDelayDefault = 5 * time.Second

	// ExternalCiliumDNSProxyName is the prefix for the external Cilium DNS proxy pods (and the daemonset).
	ExternalCiliumDNSProxyName = "cilium-dnsproxy"

	// EgressGatewayPeerASN is the default number of BGP ASN
	EgressGatewayPeerASN = 65000

	EgressGatewayPeerAddress = ""
)

var (
	// EgressGatewayCIDRsDefault is the default list of CIDRs to use when allocating egress IPs for EGW IPAM tests
	EgressGatewayCIDRsDefault = []string{"172.18.0.8/30"}

	PrivnetTestImages = map[string]string{
		// renovate: datasource=docker
		"VMImage": "quay.io/kubevirt/fedora-with-test-tooling-container-disk:v1.6.3@sha256:c43d0851eef3fe31d0a41f81876691189b5769aa85b9098dd244920c73828cb1",
	}
)
