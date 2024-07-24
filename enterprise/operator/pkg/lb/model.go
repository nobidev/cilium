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
	namespace    string
	name         string
	vip          lbVIP
	port         int32
	applications lbApplications
}

type lbVIP struct {
	name          string
	requestedIPv4 *string
	assignedIPv4  *string
}

func (r lbFrontend) getOwningResourceName() string {
	return getOwningResourceName(r.name)
}

func getOwningResourceName(parentName string) string {
	name := "lbfe-" + parentName

	// shorten to be below the max name length of k8s resources even after prefixing
	return shortener.ShortenK8sResourceName(name)
}

type lbFrontendTLSConfig struct {
	certificateSecrets []string
}

type lbApplications struct {
	httpProxy      *lbApplicationHTTPProxy
	httpsProxy     *lbApplicationHTTPSProxy
	tlsPassthrough *lbApplicationTLSPassthrough
}

func (r lbApplications) isHTTPProxyConfigured() bool {
	// return   r.applications.httpProxy != nil

	// Always return true as we need HTTP for T1->T2 HC
	return true
}

func (r lbApplications) isHTTPSProxyConfigured() bool {
	return r.httpsProxy != nil
}

func (r lbApplications) isTLSPassthroughConfigured() bool {
	return r.tlsPassthrough != nil
}

func (r lbApplications) getHTTPProxyRoutes() []lbRouteHTTP {
	if r.httpProxy == nil {
		return nil
	}

	return r.httpProxy.routes
}

func (r lbApplications) getHTTPSProxyRoutes() []lbRouteHTTPS {
	if r.httpsProxy == nil {
		return nil
	}

	return r.httpsProxy.routes
}

func (r lbApplications) getTLSPassthroughRoutes() []lbRouteTLSPassthrough {
	if r.tlsPassthrough == nil {
		return nil
	}

	return r.tlsPassthrough.routes
}

type lbApplicationHTTPProxy struct {
	routes []lbRouteHTTP
}

type lbApplicationHTTPSProxy struct {
	tlsConfig *lbFrontendTLSConfig
	routes    []lbRouteHTTPS
}

type lbApplicationTLSPassthrough struct {
	routes []lbRouteTLSPassthrough
}

type lbRouteHTTP struct {
	match   lbRouteHTTPMatch
	backend backend
}

type lbRouteHTTPS struct {
	match   lbRouteHTTPMatch
	backend backend
}

type lbRouteHTTPMatch struct {
	hostNames []string
	path      string
	pathType  pathTypeType
}

type pathTypeType int

const (
	pathTypePrefix pathTypeType = iota
	pathTypeExact
)

type lbRouteTLSPassthrough struct {
	match   lbRouteTLSPassthroughMatch
	backend backend
}

type lbRouteTLSPassthroughMatch struct {
	hostNames []string
}

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
