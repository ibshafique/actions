{{- $scan := . -}}
{{- if $scan.matches -}}

## Grype Vulnerability Scan - {{ now | date "2006-01-02T15:04:05Z" }}

**Image:** `{{ $scan.source.target.userInput | default $scan.source.target.repoDigests | default $scan.source.target }}`

{{- if (eq (len $scan.matches) 0) }}

### ✅ No Vulnerabilities Found

{{- else }}

### 🔍 Vulnerabilities Found: {{ len $scan.matches }}

| Package | Vulnerability ID | Severity | Installed Version | Fixed Version |
|---------|------------------|----------|-------------------|---------------|
{{- range $scan.matches }}
{{- $fixVersion := "N/A" }}
{{- if .vulnerability.fix.versions }}
{{- $fixVersion = index .vulnerability.fix.versions 0 }}
{{- end }}
| {{ .artifact.name }} | {{ .vulnerability.id }} | {{ .vulnerability.severity }} | {{ .artifact.version }} | {{ $fixVersion }} |
{{- end }}

{{- end }}
{{- else if $scan.source }}

## Grype Vulnerability Scan - {{ now | date "2006-01-02T15:04:05Z" }}

**Image:** `{{ $scan.source.target.userInput | default $scan.source.target }}`

### ✅ No Vulnerabilities Found

{{- else }}

## Grype Scan Returned Empty Report

{{- end }}