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
