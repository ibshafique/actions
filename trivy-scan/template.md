{{- $scan := . -}}
{{- if $scan.Results -}}

## Trivy Vulnerability Scan - {{ (time.Now).Format "2006-01-02T15:04:05Z" }}

{{- $totalVulns := 0 -}}
{{- $totalMisconfigs := 0 -}}
{{- range $scan.Results -}}
{{- if .Vulnerabilities }}{{- $totalVulns = add $totalVulns (len .Vulnerabilities) }}{{- end -}}
{{- if .Misconfigurations }}{{- $totalMisconfigs = add $totalMisconfigs (len .Misconfigurations) }}{{- end -}}
{{- end }}

{{- range $scan.Results }}

### {{ .Target }} ({{ .Type }})

{{- if .Vulnerabilities }}

#### Vulnerabilities Found: {{ len .Vulnerabilities }}

| Package | Vulnerability ID | Severity | Installed Version | Fixed Version |
|---------|------------------|----------|-------------------|---------------|
{{- range .Vulnerabilities }}
| {{ .PkgName }} | {{ .VulnerabilityID }} | {{ .Severity }} | {{ .InstalledVersion }} | {{ .FixedVersion | default "N/A" }} |
{{- end }}

{{- else }}

#### No Vulnerabilities Found

{{- end }}

{{- if .Misconfigurations }}

#### Misconfigurations Found: {{ len .Misconfigurations }}

| Type | ID | Title | Severity | Message |
|------|-----|-------|----------|---------|
{{- range .Misconfigurations }}
| {{ .Type }} | {{ .ID }} | {{ .Title }} | {{ .Severity }} | {{ .Message }} |
{{- end }}

{{- end }}
{{- end }}

{{- if and (eq $totalVulns 0) (eq $totalMisconfigs 0) }}

### Summary: No Issues Found

{{- end }}
{{- else }}

## Trivy Scan Returned Empty Report

{{- end }}
