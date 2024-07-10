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
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"

	datapathOpt "github.com/cilium/cilium/pkg/datapath/option"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"
)

const (
	userAgentName = "cilium-probe"
)

func (pr *probeImpl) sendL7Probe(config HealthCheckConfig, svcAddr, beAddr lb.L3n4Addr, probeOut chan ProbeData) {
	// create a client with proper timeout and TLS config in case of HTTPS
	d := &net.Dialer{
		ControlContext: pr.dialerConnSetup,
	}
	tr := &http.Transport{
		DialContext: d.DialContext,
	}
	client := http.Client{
		Timeout:   config.ProbeTimeout,
		Transport: tr,
	}
	if config.HTTPScheme == HealthCheckSchemeHTTPS {
		tls := &tls.Config{
			InsecureSkipVerify: true,            // #nosec G402 - health-checker does not check server's certificate
			ServerName:         config.HTTPHost, // used for SNI
		}
		tr.TLSClientConfig = tls
	}

	url := getConnURL(config, svcAddr)
	if option.Config.DatapathMode != datapathOpt.DatapathModeLBOnly ||
		!option.Config.EnableHealthDatapath {
		url = getConnURL(config, beAddr)
	}
	method := getSvcHTTPMethod(config)
	backend := getAddrStr(beAddr)
	logFields := logrus.Fields{"url": url, "method": method, "host": config.HTTPHost, "backend": backend}

	// create a request with proper method, URL and HTTP Host
	ctx := context.WithValue(context.Background(), backendAddrKey{}, backend)
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		log.WithError(err).WithFields(logFields).Debug("L7 health check failure")
		probeOut <- getProbeData(err)
		return
	}
	req.Header.Set("User-Agent", fmt.Sprintf("%s/%s", userAgentName, version.GetCiliumVersion().Version))
	req.Close = true           // do not attempt to re-use TCP connection
	req.Host = config.HTTPHost // need to set the Host explicitly, as URL contains the backend IP

	// send the request
	res, err := client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		log.WithError(err).WithFields(logFields).Debug("L7 health check failure")
		probeOut <- getProbeData(err)
		return
	}

	// consider status codes 200-399 as success
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusBadRequest {
		err = fmt.Errorf("invalid status code: %d", res.StatusCode)
		log.WithError(err).WithFields(logFields).Debug("L7 health check failure")
		probeOut <- getProbeData(err)
		return
	}

	log.WithFields(logFields).Debug("L7 health check success")

	probeOut <- getProbeData(nil)
}

func getSvcHTTPMethod(config HealthCheckConfig) string {
	switch config.HTTPMethod {
	case HealthCheckMethodHead:
		return http.MethodHead
	default:
		return http.MethodGet
	}
}

func getConnURL(config HealthCheckConfig, connAddr lb.L3n4Addr) string {
	var scheme, addr, path string
	switch config.HTTPScheme {
	case HealthCheckSchemeHTTPS:
		scheme = "https"
	default:
		scheme = "http"
	}
	if connAddr.AddrCluster.Addr().Is6() {
		addr = fmt.Sprintf("[%s]", connAddr.AddrCluster.Addr().String())
	} else {
		addr = connAddr.AddrCluster.Addr().String()
	}
	if config.HTTPPath != "" {
		path = config.HTTPPath
		if !strings.HasPrefix(path, "/") {
			path = "/" + path // make sure the path always starts with a slash
		}
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, addr, connAddr.L4Addr.Port, path)
}
