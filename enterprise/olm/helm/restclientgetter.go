/*
Copyright (C) Isovalent, Inc. - All Rights Reserved.

NOTICE: All information contained herein is, and remains the property of
Isovalent Inc and its suppliers, if any. The intellectual and technical
concepts contained herein are proprietary to Isovalent Inc and its suppliers
and may be covered by U.S. and Foreign Patents, patents in process, and are
protected by trade secret or copyright law.  Dissemination of this information
or reproduction of this material is strictly forbidden unless prior written
permission is obtained from Isovalent Inc.
*/

package helm

import (
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// RESTClientGetter is used to pass the client configuration of the controller to the helm client
type RESTClientGetter struct {
	clientConfig    *rest.Config
	restMapper      *meta.RESTMapper
	namespaceConfig namespaceClientConfig
}

// NewRESTClientGetter produces a RESTClientGetter implementing the genericclioptions.RESTClientGetter interface,
// which is required by helm actions
func NewRESTClientGetter(clientConfig *rest.Config, restMapper *meta.RESTMapper, namespace string) *RESTClientGetter {
	return &RESTClientGetter{
		clientConfig:    clientConfig,
		restMapper:      restMapper,
		namespaceConfig: namespaceClientConfig{namespace},
	}
}

func (c *RESTClientGetter) ToRESTConfig() (*rest.Config, error) {
	return rest.CopyConfig(c.clientConfig), nil
}

func (c *RESTClientGetter) ToDiscoveryClient() (discovery.CachedDiscoveryInterface, error) {
	dc, err := discovery.NewDiscoveryClientForConfig(c.clientConfig)
	if err != nil {
		return nil, fmt.Errorf("discovery client cannot be created: %w", err)
	}
	cdc := memory.NewMemCacheClient(dc)
	return cdc, err
}

func (c *RESTClientGetter) ToRESTMapper() (meta.RESTMapper, error) {
	return *c.restMapper, nil
}

func (c *RESTClientGetter) ToRawKubeConfigLoader() clientcmd.ClientConfig {
	return c.namespaceConfig
}

var _ clientcmd.ClientConfig = &namespaceClientConfig{}

type namespaceClientConfig struct {
	namespace string
}

func (c namespaceClientConfig) RawConfig() (clientcmdapi.Config, error) {
	return clientcmdapi.Config{}, nil
}

func (c namespaceClientConfig) ClientConfig() (*rest.Config, error) {
	return nil, nil
}

func (c namespaceClientConfig) Namespace() (string, bool, error) {
	return c.namespace, false, nil
}

func (c namespaceClientConfig) ConfigAccess() clientcmd.ConfigAccess {
	return nil
}
