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

package main

import (
	"crypto/tls"
	"flag"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	helmloader "helm.sh/helm/v3/pkg/chart/loader"

	ciliumiov1alpha1 "github.com/isovalent/cilium/olm/api/v1alpha1"
	"github.com/isovalent/cilium/olm/controller"
	//+kubebuilder:scaffold:imports
)

const (
	DefaultNamespace = "cilium"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(gatewayv1.Install(scheme))
	utilruntime.Must(monitoringv1.AddToScheme(scheme))
	utilruntime.Must(certmanagerv1.AddToScheme(scheme))

	utilruntime.Must(ciliumiov1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var helmPath string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", false,
		"If set the metrics endpoint is served securely")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.StringVar(&helmPath, "helm-path", "./manifests", "The path to the helm manifests.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	tlsOpts := []func(*tls.Config){}
	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	webhookServer := webhook.NewServer(webhook.Options{
		TLSOpts: tlsOpts,
	})

	labelsSelector := labels.SelectorFromSet(labels.Set{"isovalent.io/managed-by": "clife"})
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress:   metricsAddr,
			SecureServing: secureMetrics,
			TLSOpts:       tlsOpts,
		},
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "8d0e86f4.clife.isovalent.io",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Secret{}:                {Label: labelsSelector},
				&corev1.ConfigMap{}:             {Label: labelsSelector},
				&corev1.Namespace{}:             {Label: labelsSelector},
				&corev1.Service{}:               {Label: labelsSelector},
				&corev1.Endpoints{}:             {Label: labelsSelector},
				&corev1.ResourceQuota{}:         {Label: labelsSelector},
				&corev1.ServiceAccount{}:        {Label: labelsSelector},
				&appsv1.Deployment{}:            {Label: labelsSelector},
				&appsv1.StatefulSet{}:           {Label: labelsSelector},
				&appsv1.DaemonSet{}:             {Label: labelsSelector},
				&rbacv1.ClusterRole{}:           {Label: labelsSelector},
				&rbacv1.ClusterRoleBinding{}:    {Label: labelsSelector},
				&rbacv1.Role{}:                  {Label: labelsSelector},
				&rbacv1.RoleBinding{}:           {Label: labelsSelector},
				&batchv1.Job{}:                  {Label: labelsSelector},
				&batchv1.CronJob{}:              {Label: labelsSelector},
				&policyv1.PodDisruptionBudget{}: {Label: labelsSelector},
				&networkingv1.IngressClass{}:    {Label: labelsSelector},
			},
		},
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// TODO: the manifests directory is a copy of install/kubernetes/cilium directory that will need to be synced
	// Docker does not support symbolic links with targets outside of the root directory.
	chart, err := helmloader.LoadDir(helmPath)
	if err != nil {
		setupLog.Error(err, "Charts can't be loaded")
		os.Exit(1)
	}
	ns := os.Getenv("NAMESPACE")
	if ns == "" {
		ns = DefaultNamespace
	}
	if err = (&controller.CiliumConfigReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Chart:     chart,
		Namespace: ns,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "CiliumConfig")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
