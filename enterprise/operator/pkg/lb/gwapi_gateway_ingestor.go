package lb

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"net/netip"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	allHosts = "*"
)

type Input struct {
	GatewayClass       gatewayv1.GatewayClass
	GatewayClassConfig *v2alpha1.CiliumGatewayClassConfig

	Gateway        gatewayv1.Gateway
	HTTPRoutes     []gatewayv1.HTTPRoute
	Services       []corev1.Service
	EndpointSlices []discoveryv1.EndpointSlice
	AllNodes       []*slim_corev1.Node
	VIP            *isovalentv1alpha1.LBVIP
}
type gwIngestor struct {
	logger                 *slog.Logger
	defaultT1LabelSelector slim_metav1.LabelSelector
	defaultT2LabelSelector slim_metav1.LabelSelector
}

func newGWIngestor(logger *slog.Logger, defaultT1LabelSelector slim_metav1.LabelSelector, defaultT2LabelSelector slim_metav1.LabelSelector) *gwIngestor {
	return &gwIngestor{
		logger:                 logger,
		defaultT1LabelSelector: defaultT1LabelSelector,
		defaultT2LabelSelector: defaultT2LabelSelector,
	}
}

// takes the input from Gateway API, outputs lbService
func (r *gwIngestor) ingestGatewayAPItoLB(input Input, ctx context.Context) (*lbService, error) {

	svcList := input.Services
	svc := &corev1.Service{}

	retLBService := &lbService{}
	for _, s := range svcList { // gets the T1 service if it's made
		if s.Name == "lbfe-"+input.Gateway.Name {
			svc = s.DeepCopy()
		}
	}

	if svc.Name == "" && input.VIP == nil {
		// the lbvip pool hasn't created a svc yet, return nothing
		return retLBService, nil
	}

	deploy := []isovalentv1alpha1.LBDeployment{}
	t1LabelSelector, t2LabelSelector, err := r.getTierLabelSelectors(deploy)

	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve t1 and t2 node label selectors %w ", err)
	}

	t1NodeIPs, t2NodeIPs, err := r.loadT1AndT2NodeIPs(ctx, input.AllNodes, *t1LabelSelector, *t2LabelSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve T1 & T2 node label selectors: %w", err)
	}
	// get application names referred to in the HTTPRoutes of the gateway
	httprouteApps := getHTTPRoutes(input)

	// get the k8sService Ref
	referencedBackends := r.toBackends(input, httprouteApps)

	applications := r.toApplications(input)

	retLBService = &lbService{
		namespace: input.Gateway.Namespace,
		name:      input.Gateway.Name,
		vip: lbVIP{
			name:         input.VIP.Name,
			assignedIPv4: getAssignedIPv4(input.VIP),
			bindStatus:   getVIPBindStatus(svc),
		},
		// the port of the LB fof the Gateway. Currently grabbing the first listener port.
		// TODO check the listener slice is not empty
		port: int32(input.Gateway.Spec.Listeners[0].Port),
		//proxyProtocolConfig: input.Gateway.Spec.Listeners[0].Protocol,
		applications:        applications,
		referencedBackends:  referencedBackends,
		t1NodeIPv4Addresses: t1NodeIPs,
		t2NodeIPv4Addresses: t2NodeIPs,
		t1LabelSelector:     *t1LabelSelector,
		t2LabelSelector:     *t2LabelSelector,
	}
	return retLBService, nil

}

func (r *gwIngestor) getTierLabelSelectors(deployments []isovalentv1alpha1.LBDeployment) (*labels.Selector, *labels.Selector, error) {
	t1NodeLabelSelectors := []slim_metav1.LabelSelector{}
	t2NodeLabelSelectors := []slim_metav1.LabelSelector{}

	if len(deployments) > 0 {
		for _, a := range deployments {
			if a.Spec.Nodes.LabelSelectors != nil {
				t1NodeLabelSelectors = append(t1NodeLabelSelectors, a.Spec.Nodes.LabelSelectors.T1)
				t2NodeLabelSelectors = append(t2NodeLabelSelectors, a.Spec.Nodes.LabelSelectors.T2)
			}
		}
	}

	t1LS, err := r.getTierLabelSelector(r.defaultT1LabelSelector, t1NodeLabelSelectors)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get T1 label selector: %w", err)
	}

	t2LS, err := r.getTierLabelSelector(r.defaultT2LabelSelector, t2NodeLabelSelectors)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get T2 label selector: %w", err)
	}

	return t1LS, t2LS, nil
}

func (r *gwIngestor) toApplications(input Input) lbApplications {
	return lbApplications{
		httpProxy: r.toApplicationHTTP(input),
	}
}

func (r *gwIngestor) toApplicationHTTP(input Input) *lbApplicationHTTPProxy {
	httpRouteApps := getHTTPRoutes(input)
	routes := map[string][]lbRouteHTTP{}

	for _, httproute := range httpRouteApps {

		for _, rules := range httproute.Spec.Rules {
			//TODO check if the backend ref is present
			for _, backendRefVal := range rules.BackendRefs {
				pathType, path := routePathTypePrefix, "/"
				lbhttpRoute := lbRouteHTTP{
					match: lbRouteHTTPMatch{
						pathType: pathType,
						path:     path,
					},
					backendRef: backendRef{name: string(backendRefVal.Name)},
				}
				// TODO assign the routes to hostname, currently  doing *
				routes["*"] = append(routes["*"], lbhttpRoute)
			}
		}

	}

	temp := &lbServiceHTTPConfig{
		enableHTTP11: true,
		enableHTTP2:  true,
	}

	return &lbApplicationHTTPProxy{
		httpConfig: temp,
		routes:     routes,
	}
}

type routeBackendRef struct {
	name   string
	port   uint32
	weight uint32
}

func (r *gwIngestor) toReferencedBackends(httpRouteApps map[string]gatewayv1.HTTPRoute, lbBackends map[string][]lbBackend, k8sSvcRef []routeBackendRef) map[string]backend {
	refBackend := map[string]backend{}

	for _, b := range k8sSvcRef {
		refBackend[b.name] = backend{
			name:       b.name,
			typ:        0,
			lbBackends: lbBackends[b.name],
			healthCheckConfig: lbBackendHealthCheckConfig{
				http: &lbBackendHealthCheckHTTPConfig{
					host: "lb",
					path: "/health",
				},
				intervalSeconds:              15,
				timeoutSeconds:               5,
				unhealthyThreshold:           2,
				healthyThreshold:             2,
				unhealthyEdgeIntervalSeconds: 15,
				unhealthyIntervalSeconds:     15,
			},
			tcpConfig: &lbBackendTCPConfig{
				connectTimeoutSeconds: int32(5),
			},
		}
	}
	return refBackend
}

// given the list of HTTPRoutes with this GW as the parentRef,
// get the list of backendsRefs (aka the services)
// and build the lbBackend
func (r *gwIngestor) toBackends(input Input, httprouteApps map[string]gatewayv1.HTTPRoute) map[string]backend {

	res := map[string][]lbBackend{}

	k8sBackendSvcRef := []routeBackendRef{}

	for _, httproute := range httprouteApps {
		for _, val := range httproute.Spec.Rules {
			// TODO if it's a HTTPRoute Match
			if val.Matches != nil {

			}
			// TODO if it's a HTTPRoute filter
			if val.Filters != nil {

			}
			// default is just the HTTPRouteRule.BackendRef (aka just forwarding request)
			for _, backendRefVal := range val.BackendRefs {
				k8sBackendSvcRef = append(k8sBackendSvcRef, routeBackendRef{
					name:   string(backendRefVal.Name),
					port:   uint32(*backendRefVal.Port),
					weight: uint32(*backendRefVal.Weight),
				})
			}
		}
	}

	for _, svcRef := range k8sBackendSvcRef {
		addresses := []string{}

		port := r.getBackendPortFromService(input.Services, input.EndpointSlices, string(svcRef.name), uint32(svcRef.port))
		// get the addresses from endpoint slices
		addresses = append(addresses, r.getAddressesFromEndpointSlices(input.EndpointSlices, svcRef.name)...)
		res[svcRef.name] = append(res[svcRef.name], lbBackend{
			addresses: addresses,
			port:      port,
			weight:    svcRef.weight,
			// TODO figure out status
			status: 0,
		})
	}

	temp := r.toReferencedBackends(httprouteApps, res, k8sBackendSvcRef)

	return temp
}

func (r *gwIngestor) getBackendPortFromService(refK8sSvc []corev1.Service, refEndpointSlices []discoveryv1.EndpointSlice, k8sSvcName string, svcPort uint32) uint32 {

	for _, svc := range refK8sSvc {
		if svc.Name == k8sSvcName {
			for _, sp := range svc.Spec.Ports {
				if sp.Port == int32(svcPort) {
					if sp.TargetPort.IntValue() != 0 {
						return uint32(sp.TargetPort.IntValue())
					}
					if sp.TargetPort.StrVal != "" {
						for _, es := range refEndpointSlices {
							if es.GetLabels()[discoveryv1.LabelServiceName] == k8sSvcName && es.AddressType == discoveryv1.AddressTypeIPv4 {
								for _, ep := range es.Ports {
									for ep.Name != nil && *ep.Name == sp.TargetPort.StrVal && ep.Port != nil && *ep.Port != 0 {
										return uint32(*ep.Port)
									}
								}
							}
						}

					}
				}
			}
		}
	}
	r.logger.Debug("No corresponding target port found. Falling back to use the service port",
		logfields.ServiceName, k8sSvcName,
		logfields.Port, svcPort,
	)
	return svcPort
}

func (r *gwIngestor) getAddressesFromEndpointSlices(endpointSlices []discoveryv1.EndpointSlice, name string) []string {
	res := []string{}
	// get the endpoint slices associated with the applications (is there an easier way to do this?)
	for _, ep := range endpointSlices {
		if ep.Labels[discoveryv1.LabelServiceName] == name {
			for _, v := range ep.Endpoints {
				res = append(res, v.Addresses...)
			}
		}
	}

	return res
}

func getHTTPRoutes(input Input) map[string]gatewayv1.HTTPRoute {
	httprouteApps := map[string]gatewayv1.HTTPRoute{}

	// the below for-loops gets the httproutes, checks if their parent ref is the GW, then iterates through the backend to get the
	// name of the deployments. (is there an easier way to do this?)
	for _, httpR := range input.HTTPRoutes {

		for _, val := range httpR.Spec.ParentRefs {

			if string(val.Name) == input.Gateway.Name {

				for _, rule := range httpR.Spec.Rules {
					for _, b := range rule.BackendRefs {
						// but we want the backend refs
						httprouteApps[string(b.Name)] = httpR
					}
				}
			}
		}
	}
	return httprouteApps
}

func (r *gwIngestor) getTierLabelSelector(defaultLS slim_metav1.LabelSelector, deploymentLSList []slim_metav1.LabelSelector) (*labels.Selector, error) {
	defaultLabelSelector, err := slim_metav1.LabelSelectorAsSelector(&defaultLS)
	if err != nil {
		// this should never happen
		return nil, fmt.Errorf("failed to resolve default labelselector: %w", err)
	}

	if len(deploymentLSList) == 0 {
		return &defaultLabelSelector, nil
	}

	// combine the requirements of all labelselectors of LBDeployments
	combinedLabelSelector := labels.SelectorFromSet(nil) // empty label selector

	for _, ls := range deploymentLSList {
		deplLS, err := slim_metav1.LabelSelectorAsSelector(&ls)
		if err != nil {
			// In case of an error, fallback to the default labelselector. This should never be the case as this is already validated
			// by the LBDeployment reconciler.
			r.logger.Warn("Failed to parse node labelselector of LBDeployment - skipping")
			continue
		}

		reqs, _ := deplLS.Requirements()
		combinedLabelSelector = combinedLabelSelector.Add(reqs...)
	}

	return &combinedLabelSelector, nil
}

func (r *gwIngestor) loadT1AndT2NodeIPs(ctx context.Context, nodes []*slim_corev1.Node, t1LabelSelector labels.Selector, t2LabelSelector labels.Selector) ([]string, []string, error) {
	t1NodeIPs, err := r.loadNodeAddressesByLabelSelector(ctx, nodes, t1LabelSelector)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve T1 node ips: %w", err)
	}

	t2NodeIPs, err := r.loadNodeAddressesByLabelSelector(ctx, nodes, t2LabelSelector)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve T2 node ips: %w", err)
	}

	return t1NodeIPs, t2NodeIPs, nil
}
func (r *gwIngestor) loadNodeAddressesByLabelSelector(ctx context.Context, nodes []*slim_corev1.Node, selector labels.Selector) ([]string, error) {
	nodeIPs := []string{}

	for _, cn := range nodes {
		if selector.Matches(labels.Set(cn.Labels)) {
			var nodeIP string
			for _, addr := range cn.Status.Addresses {
				if addr.Type == slim_corev1.NodeInternalIP {
					a, err := netip.ParseAddr(addr.Address)
					if err != nil {
						r.logger.Debug("invalid node IP",
							logfields.NodeName, cn.Name,
							logfields.Error, err,
						)
						continue
					}

					if a.Is6() {
						// skip ipv6 addresses for now
						continue
					}

					// use first ipv4 address
					// TODO: support multiple addresses? (at least to configure the Envoy source IP filter)
					nodeIP = addr.Address
					break
				}
			}
			if nodeIP == "" {
				r.logger.Warn("Could not find InternalIP for CiliumNode",
					logfields.Resource, cn.Name,
				)
				continue
			}

			nodeIPs = append(nodeIPs, nodeIP)
		}
	}

	slices.Sort(nodeIPs)
	return nodeIPs, nil
}

//func toMapString[K, V ~string](in map[K]V) map[string]string {
//	out := make(map[string]string, len(in))
//	for k, v := range in {
//		out[string(k)] = string(v)
//	}
//	return out
//}

//func toStringSlice(s []gatewayv1.Hostname) []string {
//	res := make([]string, 0, len(s))
//	for _, h := range s {
//		res = append(res, string(h))
//	}
//	return res
//}
