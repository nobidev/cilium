//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lb

import (
	"github.com/cilium/cilium/pkg/shortener"
)

// TODO: validation method
// - tcp route -> only one route allowed
// - http and tls routes -> validate for overlapping hostnames? (with wildcards...)

type lbFrontend struct {
	namespace  string
	name       string
	staticIP   *string
	assignedIP *string
	tls        *lbFrontendTLS
	port       int32
	routes     []lbRoute
}

func (r lbFrontend) getOwningResourceName() string {
	return getOwningResourceName(r.name)
}

func getOwningResourceName(parentName string) string {
	name := "lbfe-" + parentName

	// shorten to be below the max name length of k8s resources even after prefixing
	return shortener.ShortenK8sResourceName(name)
}

type lbFrontendTLS struct {
	domainNames        []string
	certificateSecrets []string
}

type lbRoute struct {
	http    *lbRouteHTTP
	tls     *lbRouteTLS
	tcp     *lbRouteTCP
	backend backend
}

type lbRouteHTTP struct {
	tls      *lbRouteTLSConfig
	hostname string
	path     string
	pathType pathTypeType
}

type lbRouteTLSConfig struct {
	// secret resourceReference
}

type pathTypeType int

const (
	pathTypePrefix pathTypeType = iota
)

type lbRouteTLS struct {
	// hostname string
}

type lbRouteTCP struct{}

type backend struct {
	ips               []lbBackend
	hostnames         []lbBackend
	lbAlgorithm       lbAlgorithmType
	healthCheckConfig lbBackendHealthCheckConfig
}

type lbBackend struct {
	address string
	port    uint32
}

type lbAlgorithmType int

const (
	lbAlgorithmRoundRobin lbAlgorithmType = iota
)

type lbBackendHealthCheckConfig struct {
	http                         *lbBackendHealthCheckHTTPConfig
	tcp                          *lbBackendHealthCheckTCPConfig
	intervalSeconds              int
	timeoutSeconds               int
	healthyThreshold             int
	unhealthyThreshold           int
	unhealthyEdgeIntervalSeconds int
	unhealthyIntervalSeconds     int
}

type lbBackendHealthCheckHTTPConfig struct {
	host string
	path string
}

type lbBackendHealthCheckTCPConfig struct{}
