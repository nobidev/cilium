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
	"bytes"
	"fmt"

	"github.com/go-logr/logr"
	"gopkg.in/yaml.v2"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"k8s.io/cli-runtime/pkg/resource"

	helmaction "helm.sh/helm/v3/pkg/action"
	helmchart "helm.sh/helm/v3/pkg/chart"
	helmchartutil "helm.sh/helm/v3/pkg/chartutil"
	helmcli "helm.sh/helm/v3/pkg/cli"
	helmkube "helm.sh/helm/v3/pkg/kube"

	ciliumiov1alpha1 "github.com/isovalent/cilium/olm/api/v1alpha1"
)

// Install creates the required helm action and runs it
func Install(chart *helmchart.Chart, values map[string]interface{}, ccfg *ciliumiov1alpha1.CiliumConfig, logger logr.Logger) error {
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
	instAction.PostRenderer = postRenderer{
		client: actionConfig.KubeClient,
		owner:  ccfg,
	}
	// TODO: the release may only get prepared
	// and manifests compared to what is available to avoid hot looping
	// instAction.DryRun = true
	_, err := instAction.Run(chart, values)
	if err != nil {
		return err
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

type postRenderer struct {
	client helmkube.Interface
	owner  *ciliumiov1alpha1.CiliumConfig
}

func (pr postRenderer) Run(in *bytes.Buffer) (*bytes.Buffer, error) {
	resources, err := pr.client.Build(in, false)
	if err != nil {
		return nil, err
	}
	result := bytes.Buffer{}

	err = resources.Visit(func(res *resource.Info, err error) error {
		if err != nil {
			return err
		}
		obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(res.Object)
		if err != nil {
			return err
		}
		u := &unstructured.Unstructured{Object: obj}
		// Owner references cause the child resources to be deleted when the CiliumConfig is deleted.
		// An annotation could be used instead of them to avoid this behavior when desired.
		ownerRef := metav1.NewControllerRef(pr.owner, pr.owner.GetObjectKind().GroupVersionKind())
		ownerRefs := append(u.GetOwnerReferences(), *ownerRef)
		u.SetOwnerReferences(ownerRefs)
		data, err := yaml.Marshal(u.Object)
		if err != nil {
			return err
		}
		if _, err := result.WriteString("---\n" + string(data)); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}
