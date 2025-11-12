//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package logfields

const (
	// GatewayIPs is a list of gateway IPs belonging to a given egress policy
	GatewayIPs = "gatewayIPs"

	// CiliumEgressGatewayPolicyName is the name of a CiliumEgressGatewayPolicy
	IsovalentEgressGatewayPolicyName = "isovalentEgressGatewayPolicyName"

	// EgressCIDR is a CIDR used in IEGP for egress-gateway IPAM
	EgressCIDR = "egressCIDR"

	// K8sGeneration is the metadata.generation of a k8s resource.
	K8sGeneration = "k8sGeneration"

	// IsovalentSRv6EgressPolicyName is the name of a IsovalentSRv6EgressPolicy
	IsovalentSRv6EgressPolicyName = "isovalentSRv6EgressPolicyName"

	// IsovalentVRFName is the name of a IsovalentVRF
	IsovalentVRFName = "isovalentVRFName"

	// IsovalentNetworPolicyName is the name of a IsovalentNetworkPolicy
	IsovalentNetworkPolicyName = "isovalentNetworkPolicyName"

	// IsovalentClusterwideNetworPolicyName is the name of a IsovalentClusterwideNetworkPolicy
	IsovalentClusterwideNetworkPolicyName = "isovalentClusterwideNetworkPolicyName"

	// VRF is the VRF used for the SRv6 lookups.
	VRF = "vrf"

	// SID is the segment identifier used in SRv6.
	SID = "sid"

	// RoutingModes is the routing modes selected towards a given node.
	RoutingMode = "routingMode"

	// RoutingModes is a list of routing modes supported by a given node.
	RoutingModes = "routingModes"

	// InvalidRoutingModes is a list of unrecognized routing modes.
	InvalidRoutingModes = "invalidRoutingModes"

	// Omitted is the number of omitted objects.
	Omitted = "omitted"

	// ILB Flow logs messages
	SrcIP        = "srcIP"
	SrcPort      = "srcPort"
	DstIP        = "dstIP"
	DstPort      = "dstPort"
	BytesTotal   = "bytesTotal"
	PacketsTotal = "packetsTotal"
	Bytes        = "bytes"
	Packets      = "packets"
	Bandwidth    = "bandwidth"
	CleanupTime  = "cleanupTime"
	TemplateId   = "templateId"

	// Incremental is a field if the operation is incremental
	Incremental = "incremental"

	// Egress is the egress policy
	Egress = "egress"

	// Hubble flow aggregator.
	Aggregator = "aggregator"

	// Hubble exporter name.
	ExporterName = "exporter-name"

	// Hubble dropped count.
	Dropped = "dropped"

	FQDN = "fqdn"

	FromFQDNGroup = "fromFQDNGroup"

	NewResolvers = "newResolvers"

	StaleResolvers = "staleResolvers"

	Network = "network"

	SourcePort = "sourcePort"

	DestinationPort = "destinationPort"

	MissingEgressInterfaces = "missingEgressInterfaces"

	Stale = "stale"

	Component = "component"

	ToCreate = "toCreate"

	ToUpdate = "toUpdate"

	ToRemove = "toRemove"

	WorldIdentity = "worldIdentity"

	ClusterwidePrivateNetwork = "ClusterwidePrivateNetwork"

	Stdout = "stdout"
	Stderr = "stderr"
)
