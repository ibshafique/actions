#!/usr/bin/env bash
# grype-bash-v1.sh — Basic interactive Grype vulnerability scanner.
# Scans Docker images via an interactive menu prompt and generates
# per-image JSON + markdown reports with a text summary.

set -u

# -------------------------------
# Load image configuration
# -------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/images.conf"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file not found: $CONFIG_FILE"
    echo "Copy images.conf.example to images.conf and fill in your values."
    exit 1
fi

# shellcheck source=images.conf
source "$CONFIG_FILE"

SCAN_DIR="scan-results/$(date '+%Y-%m-%d_%H-%M-%S')"
SUMMARY_FILE="$SCAN_DIR/grype-summary.txt"
CRITICAL_FOUND=0

# -------------------------------
# Prompt for scan selection
# -------------------------------

echo "Which images would you like to scan?"
echo "  1) Application images"
echo "  2) Base images"
echo "  3) Both"
echo ""
read -rp "Enter choice [1/2/3]: " SCAN_CHOICE

case "$SCAN_CHOICE" in
    1) SCAN_APP=1; SCAN_BASE=0 ;;
    2) SCAN_APP=0; SCAN_BASE=1 ;;
    3) SCAN_APP=1; SCAN_BASE=1 ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

# -------------------------------
# Create output directories
# -------------------------------

mkdir -p "$SCAN_DIR"
[ "$SCAN_APP" -eq 1 ] && mkdir -p "$SCAN_DIR/app-images"
[ "$SCAN_BASE" -eq 1 ] && mkdir -p "$SCAN_DIR/base-images"

# -------------------------------
# Summary header
# -------------------------------

{
  echo "🛡️ Grype Vulnerability Scan Summary"
  echo "Organization : $ORG_NAME"
  echo "Scan Date    : $(date)"
  echo "=================================================="
  echo
} > "$SUMMARY_FILE"

# -------------------------------
# Helper: ensure image exists locally
# -------------------------------

ensure_image() {
    local image="$1"

    if docker image inspect "$image" >/dev/null 2>&1; then
        echo "📦 Image already exists locally: $image"
        return 0
    fi

    echo "📥 Image not found locally, pulling: $image"
    docker pull "$image" >/dev/null 2>&1
}

# -------------------------------
# Scan function
# -------------------------------

scan_image () {
    local repo="$1"
    local category="$2"
    local output_dir="$3"
    local image="$ORG/$repo"

    echo "Scanning $repo..."

    if ensure_image "$image"; then
        REPORT_FILE="$output_dir/$repo-grype-report.json"

        grype "$image" -o json > "$REPORT_FILE"

        CRITICAL=$(jq '[.matches[] | select(.vulnerability.severity=="Critical")] | length' "$REPORT_FILE")
        HIGH=$(jq '[.matches[] | select(.vulnerability.severity=="High")] | length' "$REPORT_FILE")
        MEDIUM=$(jq '[.matches[] | select(.vulnerability.severity=="Medium")] | length' "$REPORT_FILE")
        LOW=$(jq '[.matches[] | select(.vulnerability.severity=="Low")] | length' "$REPORT_FILE")

        # Generate human-readable markdown report
        READABLE_REPORT="$output_dir/$repo-report.md"
        {
          echo "## Grype Vulnerability Scan - $repo"
          echo ""
          echo "**Image:** \`$image\`"
          echo "**Category:** $category"
          echo "**Scan Date:** $(date)"
          echo ""
          TOTAL=$(jq '.matches | length' "$REPORT_FILE")
          if [ "$TOTAL" -gt 0 ]; then
            echo "### Vulnerabilities Found: $TOTAL"
            echo ""
            echo "| Package | CVE | Severity | Installed Version | Fixed Version |"
            echo "|---------|-----|----------|-------------------|---------------|"
            jq -r '.matches | sort_by(.vulnerability.severity) | reverse[] |
              "| \(.artifact.name) | \(.vulnerability.id) | \(.vulnerability.severity) | \(.artifact.version) | \(.vulnerability.fix.versions[0] // "N/A") |"' "$REPORT_FILE"
          else
            echo "### No Vulnerabilities Found"
          fi
        } > "$READABLE_REPORT"

        echo "✅ $repo scanned successfully"

        {
          echo "$repo ($category):"
          echo "  Critical: $CRITICAL"
          echo "  High:     $HIGH"
          echo "  Medium:   $MEDIUM"
          echo "  Low:      $LOW"
          echo
        } >> "$SUMMARY_FILE"

        if [ "$CRITICAL" -gt 0 ]; then
            CRITICAL_FOUND=1
            echo "🚨 CRITICAL vulnerabilities found in $repo"
        fi
    else
        echo "❌ Failed to pull $repo"
        echo "$repo ($category): ❌ Pull failed or access denied" >> "$SUMMARY_FILE"
        echo >> "$SUMMARY_FILE"
    fi

    echo "--------------------------------------------------"
}

# -------------------------------
# Scan application images
# -------------------------------

if [ "$SCAN_APP" -eq 1 ]; then
    echo "### Application Images ###" >> "$SUMMARY_FILE"
    echo >> "$SUMMARY_FILE"

    for repo in "${APP_IMAGES[@]}"; do
        scan_image "$repo" "application" "$SCAN_DIR/app-images"
    done
fi

# -------------------------------
# Scan base images
# -------------------------------

if [ "$SCAN_BASE" -eq 1 ]; then
    echo "### Base Images ###" >> "$SUMMARY_FILE"
    echo >> "$SUMMARY_FILE"

    for repo in "${BASE_IMAGES[@]}"; do
        scan_image "$repo" "base" "$SCAN_DIR/base-images"
    done
fi

# -------------------------------
# Final result
# -------------------------------

echo "==================================================" >> "$SUMMARY_FILE"

if [ "$CRITICAL_FOUND" -eq 1 ]; then
    echo "🚨 CRITICAL vulnerabilities detected!" >> "$SUMMARY_FILE"
    echo "🚨 One or more images contain CRITICAL vulnerabilities"
    echo "📄 See $SUMMARY_FILE for details"
    exit 1
else
    echo "✅ No CRITICAL vulnerabilities found" >> "$SUMMARY_FILE"
    echo "✅ Scan complete — no CRITICAL vulnerabilities detected"
    echo "📄 Summary written to $SUMMARY_FILE"
    exit 0
fi
