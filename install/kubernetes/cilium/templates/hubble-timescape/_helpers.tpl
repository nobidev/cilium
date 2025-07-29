{{- define "hubble.timescape.podAnnotations" -}}
{{- if .Values.hubble.timescape.rollOutPods }}
hubble-timescape-config-configmap-checksum: {{ include (print $.Template.BasePath "/hubble-timescape/timescape-configmap.yaml") . | sha256sum | quote }}
{{- if .Values.hubble.timescape.clickhouse.rollOutPods }}
hubble-timescape-clickhouse-settings-configmap-checksum: {{ include (print $.Template.BasePath "/hubble-timescape/timescape-clickhouse-configmap.yaml") . | sha256sum | quote }}
{{- end }}
{{- /* This annotation will ensure that the pod is restarted on pvc size change */}}
{{- if .Values.hubble.timescape.persistence.enabled }}
{{- with .Values.hubble.timescape.persistence.volumeSize }}
hubble-timescape-clickhouse-volume-size: {{ . }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}

{{- define "hubble.timescape.tls.enabled" -}}
{{- and .Values.hubble.timescape.enabled
(or
  (eq .Values.hubble.timescape.tls.enabled true)
  (and (kindIs "invalid" .Values.hubble.timescape.tls.enabled) .Values.hubble.tls.enabled)
)
-}}
{{- end }}

{{- define "hubble.timescape.ui.auth.enabled" -}}
{{- or
  .Values.hubble.timescape.ui.auth.enabled
  .Values.hubble.rbac.enabled
-}}
{{- end }}

{{- define "hubble.timescape.probe" -}}
grpc:
  port: 8083
{{- end }}

{{- define "hubble.timescape.servicemonitor.endpoint" -}}
- port:  {{ .port }}
  interval: {{ .values.interval | quote }}
  {{- with .values.scrapeTimeout }}
  scrapeTimeout: {{ . | quote }}
  {{- end }}
  honorLabels: true
  path: /metrics
  {{- with .values.relabelings }}
  relabelings:
  {{- toYaml . | nindent 2 }}
  {{- end }}
  {{- with .values.metricRelabelings }}
  metricRelabelings:
  {{- toYaml . | nindent 2 }}
  {{- end }}
{{- end }}

{{- define "hubble.timescape.export.extraVolumes" -}}
{{- if and
  .Values.hubble.export.timescape.enabled
  .Values.hubble.export.timescape.tls.enabled
  (or .Values.hubble.export.timescape.tls.mtls.enabled .Values.hubble.export.timescape.tls.ca.configMap.name)
}}
- name: hubble-export-timescape-tls
  projected:
    # note: the leading zero means this number is in octal representation: do not remove it
    defaultMode: 0400
    sources:
    {{- if .Values.hubble.export.timescape.tls.mtls.enabled }}
    - secret:
        name: {{ .Values.hubble.export.timescape.tls.mtls.secretName | default "hubble-export-timescape-mtls-certs" }}
        optional: true
        items:
        - key: tls.crt
          path: client.crt
        - key: tls.key
          path: client.key
    {{- end }}
    {{- if .Values.hubble.export.timescape.tls.ca.configMap.name }}
    - configMap:
        name: {{ .Values.hubble.export.timescape.tls.ca.configMap.name }}
        optional: true
        items:
        - key: {{ .Values.hubble.export.timescape.tls.ca.configMap.key }}
          path: client-ca.crt
    {{- end }}
{{- end }}
{{- end }}

{{- define "hubble.timescape.export.extraVolumeMounts" -}}
{{- if and
  .Values.hubble.export.timescape.enabled
  .Values.hubble.export.timescape.tls.enabled
  (or .Values.hubble.export.timescape.tls.mtls.enabled .Values.hubble.export.timescape.tls.ca.configMap.name)
}}
- name: hubble-export-timescape-tls
  mountPath: /var/lib/cilium/tls/hubble-export-timescape
  readOnly: true
{{- end }}
{{- end }}
