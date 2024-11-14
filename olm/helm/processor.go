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

	"github.com/go-logr/logr"

	helmaction "helm.sh/helm/v3/pkg/action"
	helmchart "helm.sh/helm/v3/pkg/chart"
	helmchartutil "helm.sh/helm/v3/pkg/chartutil"
	helmcli "helm.sh/helm/v3/pkg/cli"

	ciliumiov1alpha1 "github.com/isovalent/cilium/olm/api/v1alpha1"
)

// Install creates the required helm action and runs it
func Install(chart *helmchart.Chart, values map[string]interface{}, logger logr.Logger) error {
	settings := helmcli.New()
	actionConfig := new(helmaction.Configuration)
	if err := actionConfig.Init(settings.RESTClientGetter(), settings.Namespace(), "", func(msg string, v ...interface{}) {
		logger.V(4).Info(msg, v)
	}); err != nil {
		return err
	}
	instAction := helmaction.NewInstall(actionConfig)
	instAction.Namespace = settings.Namespace()
	instAction.ReleaseName = "cilium-release"
	// TODO: the release may only get prepared
	// and manifests compared to what is available to avoid hot looping
	// instAction.DryRun = true
	_, err := instAction.Run(chart, values)
	if err != nil {
		logger.Error(err, "Failed to run install")
	}
	return nil
}

// Values extracts the helm values from the CiliumConfig custom resource
func Values(ccfg *ciliumiov1alpha1.CiliumConfig) (helmchartutil.Values, error) {
	hv, err := helmchartutil.ReadValues(ccfg.Spec.Raw)
	if err != nil {
		return nil, fmt.Errorf("helm values cannot be read from CiliumConfig: %v", err)
	}
	return hv, nil
}
