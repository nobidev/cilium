{{- define "hubble.k8s-exporter.labels" }}
k8s-app: hubble-k8s-exporter
app.kubernetes.io/name: hubble-k8s-exporter
app.kubernetes.io/part-of: cilium
{{- end }}
