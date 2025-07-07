{{/*
_extensions.tpl contains template blocks that are intended to allow packagers
to modify or extend the default chart behaviors.
*/}}

{{/*
Allow packagers to add extra volumes to cilium-agent.
*/}}
{{- define "cilium-agent.volumes.extra" }}
{{- include "hubble.timescape.export.extraVolumes" . }}
{{- end }}

{{- define "cilium-agent.volumeMounts.extra" }}
{{- include "hubble.timescape.export.extraVolumeMounts" . }}
{{- end }}

{{/*
Allow packagers to set dnsPolicy for cilium-agent.
*/}}
{{- define "cilium-agent.dnsPolicy" }}
{{- if .Values.dnsPolicy }}
dnsPolicy: {{ .Values.dnsPolicy }}
{{- else if or
  .Values.hubble.export.timescape.enabled
  (and .Values.hubble.timescape.enabled .Values.hubble.timescape.useStreamAPI)
}}
# When Timescape export is enabled, cilium-agent needs to be able to resolve
# the Timescape service name. Since cilium-agent runs with hostNetwork: true,
# we need to set dnsPolicy to ClusterFirstWithHostNet.
dnsPolicy: ClusterFirstWithHostNet
{{- end }}
{{- end }}

{{/*
Allow packagers to add extra volumes to cilium-operator.
*/}}
{{- define "cilium-operator.volumes.extra" }}
{{- end }}

{{- define "cilium-operator.volumeMounts.extra" }}
{{- end }}

{{/*
Intentionally empty to allow downstream chart packagers to add extra
containers to hubble-relay without having to modify the deployment manifest
directly.
*/}}
{{- define "hubble-relay.containers.extra" }}
{{- if .Values.hubble.rbac.enabled -}}
{{- toYaml (list (tpl (include "container.rbac" .) . | fromYaml)) -}}
{{- end -}}
{{- end }}

{{/*
Allow packagers to add extra volumes to relay.
*/}}
{{- define "hubble-relay.volumes.extra" }}
{{- if .Values.hubble.rbac.enabled -}}
{{- $rbacVolumes := tpl `
- name: hubble-rbac-policy
  configMap:
    name: {{ .Values.hubble.rbac.policy.configMap.name }}
    defaultMode: 0400
{{- if .Values.hubble.rbac.auth.oidc.ca.configMap.name }}
- name: hubble-rbac-tls-oidc
  configMap:
    name: {{ .Values.hubble.rbac.auth.oidc.ca.configMap.name }}
    items:
    - key: {{ .Values.hubble.rbac.auth.oidc.ca.configMap.key }}
      path: hubble-oidc-provider-ca.pem
{{- end }}
` . | fromYamlArray -}}
{{- toYaml $rbacVolumes -}}
{{- end -}}
{{- end }}

{{/*
Allow packagers to modify how hubble-relay TLS is configured.

A packager may want to change when TLS is enabled or prevent users from
disabling TLS. This means the template needs to allow overriding, not just
adding, which is why this template is not empty by default, like the ones
above.
*/}}
{{- define "hubble-relay.config.tls" }}
{{- if and .Values.hubble.tls.enabled .Values.hubble.relay.tls.server.enabled (not .Values.hubble.rbac.enabled) }}
tls-relay-server-cert-file: /var/lib/hubble-relay/tls/server.crt
tls-relay-server-key-file: /var/lib/hubble-relay/tls/server.key
{{- if .Values.hubble.relay.tls.server.mtls }}
tls-relay-client-ca-files: /var/lib/hubble-relay/tls/hubble-server-ca.crt
{{- end }}
{{- else }}
disable-server-tls: true
{{- end }}
{{- end }}

{{- define "hubble-relay.config.listenAddress" -}}
{{- if .Values.hubble.rbac.enabled -}}
localhost:{{- include "hubble-relay.config.listenPort" . -}}
{{- else -}}
{{- .Values.hubble.relay.listenHost }}:{{- include "hubble-relay.config.listenPort" . -}}
{{- end -}}
{{- end }}

{{- define "hubble-relay.config.listenPort" -}}
{{- if .Values.hubble.rbac.enabled -}}
4246
{{- else -}}
{{- .Values.hubble.relay.listenPort }}
{{- end -}}
{{- end }}

{{- define "hubble-relay.service.targetPort" -}}
{{- if .Values.hubble.rbac.enabled -}}
grpc-rbac
{{- else -}}
grpc
{{- end -}}
{{- end }}

{{/*
Allow packagers to add extra configuration to certgen.
*/}}
{{- define "certgen.config.extra" -}}
{{- if eq (include "hubble.timescape.tls.enabled" .) "true" }}
{{- $certValidityStr := printf "%dh" (mul .Values.hubble.tls.auto.certValidityDuration 24) }}
    {{- if or
      (not .Values.hubble.timescape.clustermesh.primary.id)
      (eq (int64 .Values.hubble.timescape.clustermesh.primary.id) (int64 .Values.cluster.id))
    }}
    - name: hubble-timescape-server-certs
      namespace: {{ include "cilium.namespace" . }}
      commonName: "hubble-timescape"
      hosts:
      - "hubble-timescape"
      - "hubble-timescape."
      - "hubble-timescape.{{ .Release.Namespace }}.svc.cluster.local"
      - "hubble-timescape.{{ .Release.Namespace }}.svc.cluster.local."
      - "hubble-timescape.{{ .Release.Namespace }}.svc"
      - "hubble-timescape.{{ .Release.Namespace }}.svc."
      {{- range $dns := .Values.hubble.timescape.tls.server.extraDnsNames }}
      - {{ $dns | quote }}
      {{- end }}
      {{- range $ip := .Values.hubble.timescape.tls.server.extraIpAddresses }}
      - {{ $ip | quote }}
      {{- end }}
      usage:
      - signing
      - key encipherment
      - server auth
      - client auth # needed for grpc health probe
      validity: {{ $certValidityStr }}
    {{- end }}
    - name: hubble-timescape-client-certs
      namespace: {{ include "cilium.namespace" . }}
      commonName: "hubble-timescape-client"
      hosts:
      - "hubble-timescape"
      usage:
      - signing
      - key encipherment
      - client auth # needed for grpc health probe
      validity: {{ $certValidityStr }}
{{- end }}
{{- end }}

{{/*
Allow packagers to add extra configuration to certgen.
*/}}
{{- define "certgen.config.extra" -}}
{{- end }}

{{/*
Allow packagers to add extra arguments to the clustermesh-apiserver apiserver container.
*/}}
{{- define "clustermesh.apiserver.args.extra" -}}
{{- if .Values.enterprise.privateNetworks.enabled }}
- --private-networks-enabled
{{- end }}
{{- end }}

{{/*
Allow packagers to add extra arguments to the clustermesh-apiserver kvstoremesh container.
*/}}
{{- define "clustermesh.kvstoremesh.args.extra" -}}
{{- end }}
