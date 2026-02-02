{{- $scan := . -}}
{{- if $scan.source -}}

## Grype Vulnerability Scan - {{ (time.Now).Format "2006-01-02T15:04:05Z" }}

**Image:** `{{ $scan.source.target.userInput | default $scan.source.target }}`

{{- if $scan.matches }}

### 🔍 Vulnerabilities Found: {{ len $scan.matches }}

| Package | Vulnerability ID | Severity | Installed Version | Fixed Version |
|---------|------------------|----------|-------------------|---------------|
{{- range $scan.matches }}
{{- $fix := "N/A" }}
{{- with .vulnerability.fix }}{{- with .versions }}{{- $fix = index . 0 }}{{- end }}{{- end }}
| {{ .artifact.name }} | {{ .vulnerability.id }} | {{ .vulnerability.severity }} | {{ .artifact.version }} | {{ $fix }} |
{{- end }}

{{- else }}

### ✅ No Vulnerabilities Found

{{- end }}
{{- else }}

## Grype Scan Returned Empty Report

{{- end }}
