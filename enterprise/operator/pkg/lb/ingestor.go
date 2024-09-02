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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

type ingestor struct{}

func (r *ingestor) ingest(vip *isovalentv1alpha1.LBVIP, lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool, t1Service *corev1.Service) (*lbService, error) {
	applications, err := r.toApplications(lbsvc, backends)
	if err != nil {
		return nil, fmt.Errorf("failed to ingest applications: %w", err)
	}

	return &lbService{
		namespace: lbsvc.Namespace,
		name:      lbsvc.Name,
		vip: lbVIP{
			name:         lbsvc.Spec.VIPRef.Name,
			assignedIPv4: getAssignedIP(vip),
			bindStatus:   getVIPBindStatus(t1Service),
		},
		port:         lbsvc.Spec.Port,
		applications: applications,
	}, nil
}

func (*ingestor) toHTTPConfig(httpConfig *isovalentv1alpha1.LBServiceHTTPConfig) *lbServiceHTTPConfig {
	http11Enabled := true
	http2Enabled := true

	if httpConfig != nil && httpConfig.EnableHTTP11 != nil {
		http11Enabled = *httpConfig.EnableHTTP11
	}

	if httpConfig != nil && httpConfig.EnableHTTP2 != nil {
		http2Enabled = *httpConfig.EnableHTTP2
	}

	return &lbServiceHTTPConfig{
		enableHTTP11: http11Enabled,
		enableHTTP2:  http2Enabled,
	}
}

func (*ingestor) toTLSConfig(lbsvc *isovalentv1alpha1.LBService) *lbServiceTLSConfig {
	if lbsvc.Spec.Applications.HTTPSProxy == nil || lbsvc.Spec.Applications.HTTPSProxy.TLSConfig == nil {
		return nil
	}

	certificateSecretNames := []string{}
	for _, c := range lbsvc.Spec.Applications.HTTPSProxy.TLSConfig.Certificates {
		certificateSecretNames = append(certificateSecretNames, c.SecretRef.Name)
	}

	validationContextSecret := ""
	validationContextSubjectAlternativeNames := []string{}

	if lbsvc.Spec.Applications.HTTPSProxy.TLSConfig.Validation != nil {
		validationContextSecret = lbsvc.Spec.Applications.HTTPSProxy.TLSConfig.Validation.SecretRef.Name

		for _, san := range lbsvc.Spec.Applications.HTTPSProxy.TLSConfig.Validation.SubjectAlternativeNames {
			validationContextSubjectAlternativeNames = append(validationContextSubjectAlternativeNames, san.Exact)
		}
	}

	minTLSVersion := ""
	if lbsvc.Spec.Applications.HTTPSProxy.TLSConfig.MinTLSVersion != nil {
		minTLSVersion = string(*lbsvc.Spec.Applications.HTTPSProxy.TLSConfig.MinTLSVersion)
	}

	maxTLSVersion := ""
	if lbsvc.Spec.Applications.HTTPSProxy.TLSConfig.MaxTLSVersion != nil {
		maxTLSVersion = string(*lbsvc.Spec.Applications.HTTPSProxy.TLSConfig.MaxTLSVersion)
	}

	allowedCipherSuites := []string{}
	for _, cs := range lbsvc.Spec.Applications.HTTPSProxy.TLSConfig.AllowedCipherSuites {
		allowedCipherSuites = append(allowedCipherSuites, string(cs))
	}

	allowedECDHCurves := []string{}
	for _, ec := range lbsvc.Spec.Applications.HTTPSProxy.TLSConfig.AllowedECDHCurves {
		allowedECDHCurves = append(allowedECDHCurves, string(ec))
	}

	allowedSignatureAlgorithms := []string{}
	for _, sa := range lbsvc.Spec.Applications.HTTPSProxy.TLSConfig.AllowedSignatureAlgorithms {
		allowedSignatureAlgorithms = append(allowedSignatureAlgorithms, string(sa))
	}

	return &lbServiceTLSConfig{
		certificateSecrets: certificateSecretNames,
		validationContext: lbServiceTLSConfigValidationContext{
			trustedCASecretName:     validationContextSecret,
			subjectAlternativeNames: validationContextSubjectAlternativeNames,
		},
		minTLSVersion:              minTLSVersion,
		maxTLSVersion:              maxTLSVersion,
		allowedCipherSuites:        allowedCipherSuites,
		allowedECDHCurves:          allowedECDHCurves,
		allowedSignatureAlgorithms: allowedSignatureAlgorithms,
	}
}

func (r *ingestor) toApplications(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) (lbApplications, error) {
	return lbApplications{
		httpProxy:      r.toApplicationHTTP(lbsvc, backends),
		httpsProxy:     r.toApplicationHTTPS(lbsvc, backends),
		tlsPassthrough: r.toApplicationTLSPassthrough(lbsvc, backends),
	}, nil
}

func (r *ingestor) toApplicationHTTP(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) *lbApplicationHTTPProxy {
	if lbsvc.Spec.Applications.HTTPProxy == nil {
		return nil
	}

	backendIndex := map[string]*isovalentv1alpha1.LBBackendPool{}
	for _, b := range backends {
		backendIndex[b.Name] = b
	}

	routes := []lbRouteHTTP{}

	for _, lr := range lbsvc.Spec.Applications.HTTPProxy.Routes {
		routeBackend, ok := backendIndex[lr.BackendRef.Name]
		if !ok {
			// backend not present yet
			continue
		}

		pathType, path := toPath(lr.Match)

		routes = append(routes, lbRouteHTTP{
			match: lbRouteHTTPMatch{
				hostNames: r.toHTTPHostNames(lr.Match),
				pathType:  pathType,
				path:      path,
			},
			backend: backend{
				ips:         r.toIPBackends(routeBackend.Spec.Backends),
				hostnames:   []lbBackend{},
				lbAlgorithm: lbAlgorithmRoundRobin,
				healthCheckConfig: lbBackendHealthCheckConfig{
					http:                         r.toHTTPHealthCheck(&routeBackend.Spec.HealthCheck),
					tcp:                          r.toTCPHealthCheck(&routeBackend.Spec.HealthCheck),
					intervalSeconds:              int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
					timeoutSeconds:               int(*routeBackend.Spec.HealthCheck.TimeoutSeconds),
					healthyThreshold:             int(*routeBackend.Spec.HealthCheck.HealthyThreshold),
					unhealthyThreshold:           int(*routeBackend.Spec.HealthCheck.UnhealthyThreshold),
					unhealthyEdgeIntervalSeconds: int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
					unhealthyIntervalSeconds:     int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
				},
				tlsConfig:  r.toBackendTLSConfig(routeBackend.Spec.TLSConfig),
				httpConfig: r.toBackendHTTPConfig(routeBackend.Spec.HTTPConfig),
			},
		})
	}

	return &lbApplicationHTTPProxy{
		httpConfig: r.toHTTPConfig(lbsvc.Spec.Applications.HTTPProxy.HTTPConfig),
		routes:     routes,
	}
}

func (r *ingestor) toApplicationHTTPS(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) *lbApplicationHTTPSProxy {
	if lbsvc.Spec.Applications.HTTPSProxy == nil {
		return nil
	}

	backendIndex := map[string]*isovalentv1alpha1.LBBackendPool{}
	for _, b := range backends {
		backendIndex[b.Name] = b
	}

	routes := []lbRouteHTTPS{}

	for _, lr := range lbsvc.Spec.Applications.HTTPSProxy.Routes {
		routeBackend, ok := backendIndex[lr.BackendRef.Name]
		if !ok {
			// backend not present yet
			continue
		}

		pathType, path := toPath(lr.Match)

		routes = append(routes, lbRouteHTTPS{
			match: lbRouteHTTPMatch{
				hostNames: r.toHTTPHostNames(lr.Match),
				pathType:  pathType,
				path:      path,
			},
			backend: backend{
				ips:         r.toIPBackends(routeBackend.Spec.Backends),
				hostnames:   []lbBackend{},
				lbAlgorithm: lbAlgorithmRoundRobin,
				healthCheckConfig: lbBackendHealthCheckConfig{
					http:                         r.toHTTPHealthCheck(&routeBackend.Spec.HealthCheck),
					tcp:                          r.toTCPHealthCheck(&routeBackend.Spec.HealthCheck),
					intervalSeconds:              int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
					timeoutSeconds:               int(*routeBackend.Spec.HealthCheck.TimeoutSeconds),
					healthyThreshold:             int(*routeBackend.Spec.HealthCheck.HealthyThreshold),
					unhealthyThreshold:           int(*routeBackend.Spec.HealthCheck.UnhealthyThreshold),
					unhealthyEdgeIntervalSeconds: int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
					unhealthyIntervalSeconds:     int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
				},
				tlsConfig:  r.toBackendTLSConfig(routeBackend.Spec.TLSConfig),
				httpConfig: r.toBackendHTTPConfig(routeBackend.Spec.HTTPConfig),
			},
		})
	}

	return &lbApplicationHTTPSProxy{
		httpConfig: r.toHTTPConfig(lbsvc.Spec.Applications.HTTPSProxy.HTTPConfig),
		tlsConfig:  r.toTLSConfig(lbsvc),
		routes:     routes,
	}
}

func toPath(match *isovalentv1alpha1.LBServiceHTTPRouteMatch) (pathTypeType, string) {
	pathType := pathTypePrefix
	path := "/"

	if match != nil && match.Path != nil {
		if match.Path.Prefix != nil {
			pathType = pathTypePrefix
			path = *match.Path.Prefix
		} else if match.Path.Exact != nil {
			pathType = pathTypeExact
			path = *match.Path.Exact
		}
	}

	return pathType, path
}

func (r *ingestor) toApplicationTLSPassthrough(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) *lbApplicationTLSPassthrough {
	if lbsvc.Spec.Applications.TLSPassthrough == nil {
		return nil
	}

	backendIndex := map[string]*isovalentv1alpha1.LBBackendPool{}
	for _, b := range backends {
		backendIndex[b.Name] = b
	}

	routes := []lbRouteTLSPassthrough{}

	for _, lr := range lbsvc.Spec.Applications.TLSPassthrough.Routes {
		routeBackend, ok := backendIndex[lr.BackendRef.Name]
		if !ok {
			// backend not present yet
			continue
		}

		routes = append(routes, lbRouteTLSPassthrough{
			match: lbRouteTLSPassthroughMatch{
				hostNames: r.toTLSPassthroughHostNames(lr.Match),
			},
			backend: backend{
				ips:         r.toIPBackends(routeBackend.Spec.Backends),
				hostnames:   []lbBackend{},
				lbAlgorithm: lbAlgorithmRoundRobin,
				healthCheckConfig: lbBackendHealthCheckConfig{
					http:                         r.toHTTPHealthCheck(&routeBackend.Spec.HealthCheck),
					tcp:                          r.toTCPHealthCheck(&routeBackend.Spec.HealthCheck),
					intervalSeconds:              int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
					timeoutSeconds:               int(*routeBackend.Spec.HealthCheck.TimeoutSeconds),
					healthyThreshold:             int(*routeBackend.Spec.HealthCheck.HealthyThreshold),
					unhealthyThreshold:           int(*routeBackend.Spec.HealthCheck.UnhealthyThreshold),
					unhealthyEdgeIntervalSeconds: int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
					unhealthyIntervalSeconds:     int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
				},
				tlsConfig:  r.toBackendTLSConfig(routeBackend.Spec.TLSConfig),
				httpConfig: r.toBackendHTTPConfig(routeBackend.Spec.HTTPConfig),
			},
		})
	}

	return &lbApplicationTLSPassthrough{
		routes: routes,
	}
}

func (r *ingestor) toHTTPHealthCheck(hc *isovalentv1alpha1.HealthCheck) *lbBackendHealthCheckHTTPConfig {
	if hc.HTTP == nil {
		return nil
	}

	return &lbBackendHealthCheckHTTPConfig{
		host: *hc.HTTP.Host,
		path: *hc.HTTP.Path,
	}
}

func (r *ingestor) toTCPHealthCheck(hc *isovalentv1alpha1.HealthCheck) *lbBackendHealthCheckTCPConfig {
	if hc.TCP == nil {
		return nil
	}

	return &lbBackendHealthCheckTCPConfig{}
}

func (r *ingestor) toIPBackends(addresses []isovalentv1alpha1.Backend) []lbBackend {
	ipBackends := []lbBackend{}
	for _, ipAddress := range addresses {
		ipBackends = append(ipBackends, lbBackend{
			address: ipAddress.IP,
			port:    uint32(ipAddress.Port),
		})
	}

	return ipBackends
}

func (r *ingestor) toHTTPHostNames(match *isovalentv1alpha1.LBServiceHTTPRouteMatch) []string {
	if match == nil || len(match.HostNames) == 0 {
		return []string{"*"}
	}

	hostNames := []string{}
	for _, h := range match.HostNames {
		hostNames = append(hostNames, string(h))
	}

	return hostNames
}

func (r *ingestor) toTLSPassthroughHostNames(match *isovalentv1alpha1.LBServiceTLSPassthroughRouteMatch) []string {
	if match == nil || len(match.HostNames) == 0 {
		return []string{"*"}
	}

	hostNames := []string{}
	for _, h := range match.HostNames {
		hostNames = append(hostNames, string(h))
	}

	return hostNames
}

// getAssignedIP evaluates and returns the actually assigned loadbalancer IP from the LBVIP resource.
// If there's no assigned loadbalancer IP assigned yet, nil is returned instead.
func getAssignedIP(vip *isovalentv1alpha1.LBVIP) *string {
	if vip != nil {
		return vip.Status.Addresses.IPv4
	}

	return nil
}

func getVIPBindStatus(t1Service *corev1.Service) lbVIPBindStatus {
	if t1Service == nil {
		return lbVIPBindStatus{
			serviceExists:  false,
			bindSuccessful: false,
		}
	}

	for _, cond := range t1Service.Status.Conditions {
		// Map LBIPAM conditions to LBVIP conditions
		if cond.Type == "cilium.io/IPAMRequestSatisfied" {
			switch cond.Status {
			case metav1.ConditionUnknown:
				return lbVIPBindStatus{
					serviceExists:  true,
					bindSuccessful: false,
					bindIssue:      "No LB IPAM condition present yet",
				}
			case metav1.ConditionTrue:
				return lbVIPBindStatus{
					serviceExists:  true,
					bindSuccessful: true,
				}
			case metav1.ConditionFalse:
				switch cond.Reason {
				case "already_allocated_incompatible_service":
					// Special handling for the case where an IP & port combination might
					// already be used by another service.
					return lbVIPBindStatus{
						serviceExists:  true,
						bindSuccessful: false,
						bindIssue:      cond.Message,
					}
				default:
					// Pass through the message of LB IPAM.
					// Assuming users will file an issue if
					// they see this message. Most of these
					// cases should already be covered by LB IP
					// assignment to LBVIP service.
					return lbVIPBindStatus{
						serviceExists:  true,
						bindSuccessful: false,
						bindIssue:      "Unexpected condition: " + cond.Message,
					}
				}
			}
		}
	}

	return lbVIPBindStatus{
		bindSuccessful: false,
		bindIssue:      "No LB IPAM condition present yet",
	}
}

func (*ingestor) toBackendTLSConfig(tlsConfig *isovalentv1alpha1.LBBackendTLSConfig) *lbBackendTLSConfig {
	if tlsConfig == nil {
		return nil
	}

	minTLSVersion := ""
	if tlsConfig.MinTLSVersion != nil {
		minTLSVersion = string(*tlsConfig.MinTLSVersion)
	}

	maxTLSVersion := ""
	if tlsConfig.MaxTLSVersion != nil {
		maxTLSVersion = string(*tlsConfig.MaxTLSVersion)
	}

	allowedCipherSuites := []string{}
	for _, cs := range tlsConfig.AllowedCipherSuites {
		allowedCipherSuites = append(allowedCipherSuites, string(cs))
	}

	allowedECDHCurves := []string{}
	for _, ec := range tlsConfig.AllowedECDHCurves {
		allowedECDHCurves = append(allowedECDHCurves, string(ec))
	}

	allowedSignatureAlgorithms := []string{}
	for _, sa := range tlsConfig.AllowedSignatureAlgorithms {
		allowedSignatureAlgorithms = append(allowedSignatureAlgorithms, string(sa))
	}

	return &lbBackendTLSConfig{
		MinTLSVersion:              minTLSVersion,
		MaxTLSVersion:              maxTLSVersion,
		AllowedCipherSuites:        allowedCipherSuites,
		AllowedECDHCurves:          allowedECDHCurves,
		AllowedSignatureAlgorithms: allowedSignatureAlgorithms,
	}
}

func (*ingestor) toBackendHTTPConfig(httpConfig *isovalentv1alpha1.LBBackendHTTPConfig) lbBackendHTTPConfig {
	http11Enabled := true
	http2Enabled := true

	if httpConfig != nil && httpConfig.EnableHTTP11 != nil {
		http11Enabled = *httpConfig.EnableHTTP11
	}

	if httpConfig != nil && httpConfig.EnableHTTP2 != nil {
		http2Enabled = *httpConfig.EnableHTTP2
	}

	return lbBackendHTTPConfig{
		enableHTTP11: http11Enabled,
		enableHTTP2:  http2Enabled,
	}
}
