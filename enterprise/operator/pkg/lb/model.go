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

// TODO: validation method
// - tcp route -> only one route allowed
// - http and tls routes -> validate for overlapping hostnames? (with wildcards...)

type lbFrontend struct {
	namespace  string
	name       string
	staticIP   *string
	assignedIP *string
	port       int32
	routes     []lbRoute
}

type lbRoute struct {
	http    *lbRouteHttp
	tls     *lbRouteTls
	tcp     *lbRouteTcp
	backend backend
}

type lbRouteHttp struct {
	tls      *lbRouteTlsConfig
	hostname string
	path     string
	pathType pathTypeType
}

type lbRouteTlsConfig struct {
	// secret resourceReference
}

type pathTypeType int

const (
	pathTypePrefix pathTypeType = iota
)

type lbRouteTls struct {
	// hostname string
}

type lbRouteTcp struct{}

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
	http                         *lbBackendHealthCheckHttpConfig
	tcp                          *lbBackendHealthCheckTcpConfig
	intervalSeconds              int
	timeoutSeconds               int
	healthyThreshold             int
	unhealthyThreshold           int
	unhealthyEdgeIntervalSeconds int
	unhealthyIntervalSeconds     int
}

type lbBackendHealthCheckHttpConfig struct {
	host string
	path string
}

type lbBackendHealthCheckTcpConfig struct{}
