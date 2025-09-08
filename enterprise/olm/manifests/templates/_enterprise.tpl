{{/*
Enterprise-only cilium-config entries
*/}}

{{- define "enterprise.cilium-config" }}

# Configuration options to enable overlapping PodCIDR support for clustermesh
{{- /* We additionally fallback to the specific setting used in v1.13-ce for backward compatibility */}}
enable-cluster-aware-addressing: {{ .Values.enterprise.clustermesh.enableOverlappingPodCIDRSupport | default .Values.clustermesh.enableOverlappingPodCIDRSupport | default "false" | quote }}
enable-inter-cluster-snat: {{ .Values.enterprise.clustermesh.enableOverlappingPodCIDRSupport | default .Values.clustermesh.enableOverlappingPodCIDRSupport | default "false" | quote }}

# Configuration options to enable SRv6 support
enable-srv6:               {{ .Values.enterprise.srv6.enabled            | default "false"   | quote }}
srv6-encap-mode:           {{ .Values.enterprise.srv6.encapMode          | default "reduced" | quote }}
srv6-locator-pool-enabled: {{ .Values.enterprise.srv6.locatorPoolEnabled | default "false"   | quote }}

{{- if .Values.enterprise.bgpControlPlane.enabled }}
enable-enterprise-bgp-control-plane: "true"
enable-bgp-control-plane: "true"
bgp-secrets-namespace: {{ .Values.enterprise.bgpControlPlane.secretsNamespace.name | quote }}
# Status reporting for OSS BGP control plane is disabled when enterprise BGP control plane is enabled.
# Enterprise BGP control plane status reporting is enabled by default, but can be disabled by the user.
enable-bgp-control-plane-status-report: "false"
enable-enterprise-bgp-control-plane-status-report: {{ .Values.enterprise.bgpControlPlane.statusReport.enabled | quote }}
# Service health-checking integration in BGP control plane
enable-bgp-svc-health-checking: {{ .Values.enterprise.bgpControlPlane.enableServiceHealthChecking | default "false" | quote }}
enable-statedb-neighbor-sync: "true"
router-advertisement-interval: {{ .Values.enterprise.bgpControlPlane.routerAdvertisementInterval | quote }}
bgp-router-id-allocation-mode: {{ .Values.enterprise.bgpControlPlane.routerIDAllocation.mode | quote }}
{{- end }}

# BFD subsystem
enable-bfd: {{ .Values.enterprise.bfd.enabled | default "false" | quote }}

# Configuration options to enable multicast support
multicast-enabled: {{ .Values.enterprise.multicast.enabled | default "false" | quote }}

{{- if .Values.enterprise.ciliummesh.enabled }}
enable-cilium-mesh: "true"
{{- end }}
{{- if .Values.enterprise.egressGatewayHA.enabled }}
enable-ipv4-egress-gateway-ha: "true"
{{- end }}
{{- if hasKey .Values.enterprise.egressGatewayHA "reconciliationTriggerInterval" }}
egress-gateway-ha-reconciliation-trigger-interval: {{ .Values.enterprise.egressGatewayHA.reconciliationTriggerInterval | quote }}
{{- end }}
{{- if hasKey .Values.enterprise.egressGatewayHA "socketTermination" }}
enable-egress-gateway-ha-socket-termination: {{ .Values.enterprise.egressGatewayHA.socketTermination.enabled | default "false" | quote }}
{{- end }}
{{- if .Values.enterprise.egressGatewayHA.maxPolicyEntries }}
egress-gateway-ha-policy-map-max: {{ .Values.enterprise.egressGatewayHA.maxPolicyEntries | quote }}
{{- end }}
{{- if hasKey .Values.enterprise.egressGatewayHA "healthcheckTimeout" }}
egress-gateway-ha-healthcheck-timeout: {{ .Values.enterprise.egressGatewayHA.healthcheckTimeout | quote }}
{{- else if hasKey .Values.egressGateway "healthcheckTimeout" }}
egress-gateway-ha-healthcheck-timeout: {{ .Values.egressGateway.healthcheckTimeout | quote }}
{{- end }}

{{- if .Values.enterprise.clustermesh.mixedRoutingMode.enabled }}
fallback-routing-mode: tunnel
{{- end }}


feature-gates-approved: {{ .Values.enterprise.featureGate.approved | join "," | quote }}
feature-gates-strict: {{ .Values.enterprise.featureGate.strict | quote }}
{{- with .Values.enterprise.featureGate.minimumMaturity }}
feature-gates-minimum-maturity: {{ . | quote }}
{{- end }}

{{- if .Values.enterprise.multiNetwork.enabled }}
# Multi-network support
enable-multi-network: {{ .Values.enterprise.multiNetwork.enabled | quote }}
{{- if hasKey .Values.enterprise.multiNetwork "autoDirectNodeRoutes" }}
multi-network-auto-direct-node-routes: {{ .Values.enterprise.multiNetwork.autoDirectNodeRoutes | quote }}
{{- end }}
{{- if hasKey .Values.enterprise.multiNetwork "autoCreateDefaultPodNetwork" }}
auto-create-default-pod-network: {{ .Values.enterprise.multiNetwork.autoCreateDefaultPodNetwork | quote }}
{{- end }}
{{- end }}


# If user did not provide any extraConfig or didn't provide export-file-path,
# use the default value for export and aggregation.

{{- $defaultExportFilePath := "" }}
{{- $defaultExportAggregation := "" }}
{{- $defaultExportAggregationStateFilter := "" }}

# For cilium version <1.16 we enable export to /var/run/cilium/hubble by
# default.
{{- if semverCompare "<1.16" (default "1.16" .Values.upgradeCompatibility)}}
{{- $defaultExportFilePath = "/var/run/cilium/hubble/hubble.log"}}
{{- end }}

# If integrated Timescape is enabled we enable export and export aggregation by
# default. If the export-file-path is set by the user we do not enable export
# aggregation by default to not change the existing behavior.
{{- if and .Values.hubble.timescape.enabled (or (not .Values.extraConfig) (not (hasKey .Values.extraConfig "export-file-path")))}}
{{- $defaultExportFilePath = "/var/run/cilium/hubble/hubble.log"}}
{{- $defaultExportAggregation = "connection" }}
{{- $defaultExportAggregationStateFilter = "new error" }}
{{- end }}

{{- if or (not .Values.extraConfig) (not (hasKey .Values.extraConfig "export-file-path"))}}
export-file-path: {{ $defaultExportFilePath | quote }}
{{- end }}
{{- if or (not .Values.extraConfig) (not (hasKey .Values.extraConfig "export-aggregation"))}}
export-aggregation: {{ $defaultExportAggregation | quote }}
{{- end }}
{{- if or (not .Values.extraConfig) (not (hasKey .Values.extraConfig "export-aggregation-state-filter"))}}
export-aggregation-state-filter: {{ $defaultExportAggregationStateFilter | quote }}
{{- end }}

{{- if .Values.hubble.export }}
{{- if .Values.hubble.export.static.enabled }}
hubble-export-format-version: {{ .Values.hubble.export.static.formatVersion | quote }}
{{- with .Values.hubble.export.static.fileRotationInterval }}
hubble-export-file-rotation-interval: {{ . | quote }}
{{- end }}
{{- with .Values.hubble.export.static.rateLimit }}
hubble-export-rate-limit: {{ . | quote }}
{{- end }}
{{- with .Values.hubble.export.static.overrideNodeName }}
hubble-export-node-name: {{ . | quote }}
{{- end }}
{{- with .Values.hubble.export.static.aggregation }}
hubble-export-aggregation: {{ . | join " " | quote }}
{{- end }}
{{- with .Values.hubble.export.static.aggregationIgnoreSourcePort }}
hubble-export-aggregation-ignore-source-port: {{ . | quote }}
{{- end }}
{{- with .Values.hubble.export.static.aggregationRenewTTL }}
hubble-export-aggregation-renew-ttl: {{ . | quote }}
{{- end }}
{{- with .Values.hubble.export.static.aggregationStateFilter }}
hubble-export-aggregation-state-filter: {{ . | join " " | quote }}
{{- end }}
{{- with .Values.hubble.export.static.aggregationTTL }}
hubble-export-aggregation-ttl: {{ . | quote }}
{{- end }}
{{- end }}
{{- end }}

enable-phantom-services: {{ .Values.enterprise.clustermesh.phantomServices.enabled | quote}}

{{- if .Values.enterprise.encryption.policy.enabled }}
enable-encryption-policy: {{ .Values.enterprise.encryption.policy.enabled | quote }}
{{- end }}

{{- if .Values.enterprise.loadbalancer.enabled }}
loadbalancer-cp-enabled: "true"
loadbalancer-cp-secrets-namespace: {{ .Values.envoyConfig.secretsNamespace.name | quote }}
loadbalancer-metrics-enabled: "true"
enable-active-lb-health-checking: "true"
enable-ipip-termination: "true"
bpf-lb-ipip-sock-mark: "true"
{{- end }}

{{- if .Values.enterprise.healthServerWithoutActiveChecks.enabled }}
  enable-health-server-without-active-checks: "true"
{{- else }}
  enable-health-server-without-active-checks: "false"
{{- end }}

{{- end }}
