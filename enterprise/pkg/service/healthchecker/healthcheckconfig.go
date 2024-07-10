// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package healthchecker

import (
	"fmt"

	"github.com/cilium/cilium/pkg/time"
)

// HealthCheckState is the health check state for a given service.
type HealthCheckState uint32

const (
	HealthCheckDisabled = iota
	HealthCheckEnabledNative
	HealthCheckEnabledExternal
)

// HealthCheckScheme is the health check scheme for L7 probes.
type HealthCheckScheme uint32

const (
	HealthCheckSchemeHTTP = iota
	HealthCheckSchemeHTTPS
)

const (
	HealthCheckSchemeHTTPString  = "http"
	HealthCheckSchemeHTTPSString = "https"
)

// HealthCheckMethod is the health check method for L7 probes.
type HealthCheckMethod uint32

const (
	HealthCheckMethodGet = iota
	HealthCheckMethodHead
)

const (
	HealthCheckMethodGetString  = "get"
	HealthCheckMethodHeadString = "head"
)

// HealthCheckConfig represents the current health check config
// of a given service.
type HealthCheckConfig struct {
	State              HealthCheckState
	L7                 bool
	ProbeInterval      time.Duration
	ProbeTimeout       time.Duration
	QuarantineTimeout  time.Duration
	ThresholdHealthy   int
	ThresholdUnhealthy int
	HTTPScheme         HealthCheckScheme
	HTTPMethod         HealthCheckMethod
	HTTPPath           string
	HTTPHost           string
}

func defaultHealthCheckConfig() HealthCheckConfig {
	return HealthCheckConfig{
		State:              HealthCheckDisabled,
		ProbeInterval:      time.Duration(3) * time.Second,
		ProbeTimeout:       time.Duration(1) * time.Second,
		QuarantineTimeout:  time.Duration(30) * time.Second,
		HTTPScheme:         HealthCheckSchemeHTTP,
		HTTPMethod:         HealthCheckMethodGet,
		ThresholdHealthy:   3,
		ThresholdUnhealthy: 3,
	}
}

func (hc *HealthCheckConfig) DeepEqual(other *HealthCheckConfig) bool {
	return hc.State == other.State &&
		hc.L7 == other.L7 &&
		hc.ProbeInterval == other.ProbeInterval &&
		hc.ProbeTimeout == other.ProbeTimeout &&
		hc.QuarantineTimeout == other.QuarantineTimeout &&
		hc.ThresholdHealthy == other.ThresholdHealthy &&
		hc.ThresholdUnhealthy == other.ThresholdUnhealthy &&
		hc.HTTPScheme == other.HTTPScheme &&
		hc.HTTPMethod == other.HTTPMethod &&
		hc.HTTPPath == other.HTTPPath &&
		hc.HTTPHost == other.HTTPHost
}

func (hc HealthCheckConfig) String() string {
	scheme := "inv"
	if hc.HTTPScheme == HealthCheckSchemeHTTP {
		scheme = HealthCheckSchemeHTTPString
	} else if hc.HTTPScheme == HealthCheckSchemeHTTPS {
		scheme = HealthCheckSchemeHTTPSString
	}

	method := "inv"
	if hc.HTTPMethod == HealthCheckMethodGet {
		method = HealthCheckMethodGetString
	} else if hc.HTTPMethod == HealthCheckMethodHead {
		method = HealthCheckMethodHeadString
	}

	return fmt.Sprintf("[ state:%d l7:%t probe-interval:%s probe-timeout:%s quarantine-timeout:%s threshold-healthy:%d threshold-unhealthy:%d http-path:%s http-method:%s http-host:%s http-scheme:%s ]",
		int(hc.State), hc.L7, hc.ProbeInterval, hc.ProbeTimeout,
		hc.QuarantineTimeout, int(hc.ThresholdHealthy),
		int(hc.ThresholdUnhealthy), hc.HTTPPath, method,
		hc.HTTPHost, scheme)
}
