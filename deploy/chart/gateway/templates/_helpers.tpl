{{- define "gateway.cpImage" -}}
{{ .Values.controlPlane.image.repository }}:{{ .Values.controlPlane.image.tag | default .Chart.AppVersion }}
{{- end }}

{{- define "gateway.dpImage" -}}
{{ .Values.dataPlane.image.repository }}:{{ .Values.dataPlane.image.tag | default .Chart.AppVersion }}
{{- end }}
