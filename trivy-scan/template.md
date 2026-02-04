{{- $scan := . -}}
{{- if $scan.Results -}}

## Trivy Vulnerability Scan - {{ (time.Now).Format "2006-01-02T15:04:05Z" }}

{{- $totalVulns := 0 -}}
{{- $totalMisconfigs := 0 -}}
{{- range $scan.Results -}}
{{- $vulns := index . "Vulnerabilities" | default coll.Slice -}}
{{- $misconfigs := index . "Misconfigurations" | default coll.Slice -}}
{{- $totalVulns = add $totalVulns (len $vulns) -}}
{{- $totalMisconfigs = add $totalMisconfigs (len $misconfigs) -}}
{{- end }}

{{- range $scan.Results }}
{{- $vulns := index . "Vulnerabilities" | default coll.Slice -}}
{{- $misconfigs := index . "Misconfigurations" | default coll.Slice }}

### {{ .Target }} ({{ .Type }})

{{- if $vulns }}

#### Vulnerabilities Found: {{ len $vulns }}

| Package | Vulnerability ID | Severity | Installed Version | Fixed Version |
|---------|------------------|----------|-------------------|---------------|
{{- range $vulns }}
| {{ .PkgName }} | {{ .VulnerabilityID }} | {{ .Severity }} | {{ .InstalledVersion }} | {{ index . "FixedVersion" | default "N/A" }} |
{{- end }}

{{- else }}

#### No Vulnerabilities Found

{{- end }}

{{- if $misconfigs }}

#### Misconfigurations Found: {{ len $misconfigs }}

| Type | ID | Title | Severity | Message |
|------|-----|-------|----------|---------|
{{- range $misconfigs }}
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
