{{- define "hubble.k8s-exporter.labels" }}
k8s-app: hubble-k8s-exporter
app.kubernetes.io/name: hubble-k8s-exporter
app.kubernetes.io/part-of: cilium
{{- end }}

{{- define "hubble.k8s-exporter.enabled" -}}
{{- or .Values.hubble.k8sExporter.enabled
  (and
    (kindIs "invalid" .Values.hubble.k8sExporter.enabled)
    .Values.hubble.timescape.enabled
    (not .Values.hubble.timescape.ingester.k8sImporter.enabled)
  )
-}}
{{- end }}

