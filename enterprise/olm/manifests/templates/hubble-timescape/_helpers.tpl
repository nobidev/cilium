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
exec:
  command:
  - /usr/bin/grpc_health_probe
  - -addr=localhost:4244
  {{- if and (not .Values.hubble.rbac.enabled) (eq (include "hubble.timescape.tls.enabled" .) "true") }}
  - -tls
  - -tls-ca-cert=/var/lib/hubble-timescape/tls/server.crt
  - -tls-server-name=hubble-timescape
  {{- end }}
{{- end }}
