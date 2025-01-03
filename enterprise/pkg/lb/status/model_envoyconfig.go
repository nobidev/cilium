// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

type EnvoyConfigModel struct {
	Configs []struct {
		Type                  string `json:"@type"`
		DynamicActiveClusters []struct {
			Cluster struct {
				Name string `json:"name"`
			} `json:"cluster,omitempty"`
		} `json:"dynamic_active_clusters,omitempty"`
		DynamicEndpointConfigs []struct {
			EndpointConfig struct {
				ClusterName string `json:"cluster_name"`
				Endpoints   []struct {
					LbEndpoints []struct {
						Endpoint struct {
							Address struct {
								SocketAddress struct {
									Address   string `json:"address"`
									PortValue int    `json:"port_value"`
								} `json:"socket_address"`
							} `json:"address"`
						} `json:"endpoint"`
						HealthStatus string `json:"health_status"`
					} `json:"lb_endpoints"`
				} `json:"endpoints"`
			} `json:"endpoint_config"`
		} `json:"dynamic_endpoint_configs,omitempty"`
		DynamicListeners []struct {
			Name        string `json:"name"`
			ActiveState struct {
				Listener struct {
					Name    string `json:"name"`
					Address struct {
						SocketAddress struct {
							Address   string `json:"address"`
							PortValue int    `json:"port_value"`
						} `json:"socket_address"`
					} `json:"address"`
				} `json:"listener"`
			} `json:"active_state"`
		} `json:"dynamic_listeners,omitempty"`
		DynamicRouteConfigs []struct {
			RouteConfig struct {
				Name string `json:"name"`
			} `json:"route_config,omitempty"`
		} `json:"dynamic_route_configs,omitempty"`
		DynamicActiveSecrets []struct {
			Name   string `json:"name"`
			Secret struct {
				Name string `json:"name"`
			} `json:"secret,omitempty"`
		} `json:"dynamic_active_secrets,omitempty"`
	} `json:"configs"`
}
