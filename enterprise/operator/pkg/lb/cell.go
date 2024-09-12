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

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlRuntime "sigs.k8s.io/controller-runtime"

	"github.com/cilium/cilium/operator/pkg/secretsync"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

var Cell = cell.Module(
	"loadbalancer-controlplane",
	"LoadBalancer control plane",

	//exhaustruct:ignore
	cell.Config(Config{}),
	cell.Invoke(registerReconcilers),
	cell.Provide(registerSecretSync),
	cell.ProvidePrivate(newNodeSource),
)

type Config struct {
	LoadBalancerCPEnabled                     bool
	LoadBalancerCPSecretsNamespace            string
	LoadBalancerCPAccessLogEnableTCP          bool
	LoadBalancerCPAccessLogFormatTCP          string
	LoadBalancerCPAccessLogFormatHTTP         string
	LoadBalancerCPAccessLogFormatTLS          string
	LoadBalancerCPAccessLogExcludeHC          bool
	LoadBalancerCPRequestIDGenerate           bool
	LoadBalancerCPRequestIDPreserve           bool
	LoadBalancerCPRequestIDResponse           bool
	LoadBalancerCPHTTPServerName              string
	LoadBalancerCPT1HCProbeTimeoutSeconds     uint
	LoadBalancerCPT2HCProbeMinHealthyBackends uint
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("loadbalancer-cp-enabled", false, "Whether or not the LoadBalancer control plane is enabled.")
	flags.String("loadbalancer-cp-secrets-namespace", "cilium-secrets", "Namespace that should be used when syncing TLS secrets used by the LoadBalancer control plane.")
	flags.Bool("loadbalancer-cp-accesslog-enable-tcp", false, "Whether Envoy Access Log should be enabled for the TCP listener on the T2 Envoy by the LoadBalancer control plane")
	flags.String("loadbalancer-cp-accesslog-format-tcp", "[%START_TIME%][access][tcp] \"%PROTOCOL%\" %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION% \"%STREAM_ID%\" \"%CONNECTION_ID%\" \"%UPSTREAM_CONNECTION_ID%\" \"%UPSTREAM_HOST%\" \"%DOWNSTREAM_TLS_CIPHER%\" \"%DOWNSTREAM_TLS_VERSION%\" \"%DOWNSTREAM_DIRECT_REMOTE_ADDRESS%\" \"%DOWNSTREAM_REMOTE_ADDRESS%\" \"%DOWNSTREAM_TRANSPORT_FAILURE_REASON%\"", "Envoy Access Log format for the TCP listener that should be configured on T2 Envoy by the LoadBalancer control plane (without the trailing newline)")
	flags.String("loadbalancer-cp-accesslog-format-http", "[%START_TIME%][access][http] \"%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%\" %RESPONSE_CODE% %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION% %RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)% \"%REQ(X-FORWARDED-FOR)%\" \"%REQ(USER-AGENT)%\" \"%REQ(X-REQUEST-ID)%\" \"%STREAM_ID%\" \"%CONNECTION_ID%\" \"%UPSTREAM_CONNECTION_ID%\" \"%REQ(:AUTHORITY)%\" \"%UPSTREAM_HOST%\" \"%DOWNSTREAM_TLS_CIPHER%\" \"%DOWNSTREAM_TLS_VERSION%\" \"%DOWNSTREAM_TLS_SESSION_ID%\" \"%DOWNSTREAM_DIRECT_REMOTE_ADDRESS%\" \"%DOWNSTREAM_REMOTE_ADDRESS%\" \"%UPSTREAM_TLS_CIPHER%\" \"%UPSTREAM_TLS_VERSION%\" \"%UPSTREAM_TLS_SESSION_ID%\" \"%UPSTREAM_TRANSPORT_FAILURE_REASON%\"", "Envoy Access Log format for HTTP requests that should be configured on T2 Envoy by the LoadBalancer control plane (without the trailing newline)")
	flags.String("loadbalancer-cp-accesslog-format-tls", "[%START_TIME%][access][tls] %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION% \"%STREAM_ID%\" \"%CONNECTION_ID%\" \"%UPSTREAM_CONNECTION_ID%\" \"%UPSTREAM_HOST%\" \"%DOWNSTREAM_TLS_CIPHER%\" \"%DOWNSTREAM_TLS_VERSION%\" \"%DOWNSTREAM_TLS_SESSION_ID%\" \"%DOWNSTREAM_DIRECT_REMOTE_ADDRESS%\" \"%DOWNSTREAM_REMOTE_ADDRESS%\" \"%UPSTREAM_TLS_CIPHER%\" \"%UPSTREAM_TLS_VERSION%\" \"%UPSTREAM_TLS_SESSION_ID%\"", "Envoy Access Log format for TLS requests that should be configured on T2 Envoy by the LoadBalancer control plane (without the trailing newline)")
	flags.Bool("loadbalancer-cp-accesslog-exclude-hc", true, "Whether or not the LoadBalancer control plane should configure T2 Envoy to exclude health check requests from the access log")
	flags.Bool("loadbalancer-cp-requestid-generate", true, "Whether or not the LoadBalancer control plane should configure T2 Envoy to generate the X-Request-ID HTTP header")
	flags.Bool("loadbalancer-cp-requestid-preserve", false, "Whether or not the LoadBalancer control plane should configure T2 Envoy to preserve any existing X-Request-ID HTTP header")
	flags.Bool("loadbalancer-cp-requestid-response", false, "Whether or not the LoadBalancer control plane should configure T2 Envoy to add the X-Request-ID HTTP header to the response")
	flags.String("loadbalancer-cp-http-server-name", "ilb", "Server name that is used when writing the server header in T2 HTTP responses")
	flags.Uint("loadbalancer-cp-t1-hc-probe-timeout-seconds", 5, "Probe timeout in seconds for T1 -> T2 health checks")
	flags.Uint("loadbalancer-cp-t2-hc-probe-min-healthy-backends", 20, "The minimum percentage of backend that must be healthy from T2 point of view in order to send traffic from T1 to it")
}

type reconcilerParams struct {
	cell.In

	Logger    logrus.FieldLogger
	Lifecycle cell.Lifecycle
	JobGroup  job.Group
	Config    Config

	CtrlRuntimeManager ctrlRuntime.Manager
	Scheme             *runtime.Scheme

	NodeSource *ciliumNodeSource
}

func registerReconcilers(params reconcilerParams) error {
	if !params.Config.LoadBalancerCPEnabled {
		return nil
	}

	if err := isovalentv1alpha1.AddToScheme(params.Scheme); err != nil {
		return fmt.Errorf("failed to add scheme: %w", err)
	}

	lbServiceReconciler := newLbServiceReconciler(params.Logger, params.CtrlRuntimeManager.GetClient(), params.Scheme, params.NodeSource, &ingestor{logger: params.Logger},
		reconcilerConfig{
			SecretsNamespace: params.Config.LoadBalancerCPSecretsNamespace,
			ServerName:       params.Config.LoadBalancerCPHTTPServerName,
			AccessLog: reconcilerAccesslogConfig{
				EnableTCP:  params.Config.LoadBalancerCPEnabled,
				FormatTCP:  params.Config.LoadBalancerCPAccessLogFormatTCP,
				FormatHTTP: params.Config.LoadBalancerCPAccessLogFormatHTTP,
				FormatTLS:  params.Config.LoadBalancerCPAccessLogFormatTLS,
				ExcludeHC:  params.Config.LoadBalancerCPAccessLogExcludeHC,
			},
			RequestID: reconcilerRequestIDConfig{
				Generate: params.Config.LoadBalancerCPRequestIDGenerate,
				Preserve: params.Config.LoadBalancerCPRequestIDPreserve,
				Response: params.Config.LoadBalancerCPRequestIDResponse,
			},
			T1T2HealthCheck: reconcilerT1T2HealthCheckConfig{
				T1ProbeTimeoutSeconds:              params.Config.LoadBalancerCPT1HCProbeTimeoutSeconds,
				T2ProbeMinHealthyBackendPercentage: params.Config.LoadBalancerCPT2HCProbeMinHealthyBackends,
			},
		})

	lbVIPReconciler := newLBVIPReconciler(
		lbVIPReconcilerParams{
			logger: params.Logger,
			client: params.CtrlRuntimeManager.GetClient(),
			scheme: params.Scheme,
		})

	lbBackendPoolReconciler := newLbBackendPoolReconciler(
		params.Logger,
		params.CtrlRuntimeManager.GetClient(),
	)

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(hookContext cell.HookContext) error {
			// Register reconcilers to manager in lifecycle to ensure that CRDs are installed on the cluster
			if err := lbServiceReconciler.SetupWithManager(params.CtrlRuntimeManager); err != nil {
				return fmt.Errorf("failed to setup LBService reconciler: %w", err)
			}

			if err := lbVIPReconciler.SetupWithManager(params.CtrlRuntimeManager); err != nil {
				return fmt.Errorf("failed to setup LBVIP reconciler: %w", err)
			}

			if err := lbBackendPoolReconciler.SetupWithManager(params.CtrlRuntimeManager); err != nil {
				return fmt.Errorf("failed to setup LBBackendPool reconciler: %w", err)
			}

			return nil
		},
	})

	return nil
}

// registerSecretSync registers the LoadBalancer controlplane for secret synchronization based on TLS secrets referenced
// by the LBServices.
func registerSecretSync(params reconcilerParams) secretsync.SecretSyncRegistrationOut {
	if !params.Config.LoadBalancerCPEnabled {
		return secretsync.SecretSyncRegistrationOut{}
	}

	return secretsync.SecretSyncRegistrationOut{
		SecretSyncRegistration: &secretsync.SecretSyncRegistration{
			RefObject:            &isovalentv1alpha1.LBService{},
			RefObjectEnqueueFunc: enqueueTLSSecrets(params.CtrlRuntimeManager.GetClient(), params.Logger),
			RefObjectCheckFunc:   isReferencedByLBService,
			SecretsNamespace:     params.Config.LoadBalancerCPSecretsNamespace,
		},
	}
}
