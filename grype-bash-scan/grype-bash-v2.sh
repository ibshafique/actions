#!/usr/bin/env bash
# grype-bash-v2.sh — Improved Grype vulnerability scanner with CLI args,
# dependency checks, single-jq-call efficiency, deduplication, digest
# tracking, configurable fail severity, progress counter, and --no-json flag.

set -euo pipefail

# -------------------------------
# Dependency check
# -------------------------------

for cmd in docker grype jq; do
    command -v "$cmd" >/dev/null || { echo "Error: '$cmd' is required but not found."; exit 1; }
done

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

# -------------------------------
# Defaults & configuration
# -------------------------------

SCAN_DIR="scan-results/$(date '+%Y-%m-%d_%H-%M-%S')"
SUMMARY_FILE="$SCAN_DIR/grype-summary.txt"
CRITICAL_FOUND=0
FAIL_SEVERITY="${FAIL_SEVERITY:-Critical}"  # Set to "High" to also fail on High
KEEP_JSON=1
SCAN_APP=""
SCAN_BASE=""
SINGLE_IMAGE=""
IMAGE_REF=""
IMAGE_COUNT=0
CURRENT_IMAGE=0

# -------------------------------
# Usage
# -------------------------------

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --app              Scan application images only"
    echo "  --base             Scan base images only"
    echo "  --all              Scan both image groups"
    echo "  --image <name>     Scan a single image by name from the config arrays"
    echo "  --image-ref <ref>  Scan an arbitrary image reference (e.g. nginx:latest)"
    echo "  --no-json          Remove raw JSON reports after generating markdown"
    echo "  --help             Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  FAIL_SEVERITY  Minimum severity to trigger exit 1 (default: Critical)"
    echo "                 Set to 'High' to also fail on High vulnerabilities."
    echo ""
    echo "If no option is provided, an interactive prompt is shown."
    exit 0
}

# -------------------------------
# Parse CLI arguments
# -------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --app)       SCAN_APP=1; SCAN_BASE=0 ;;
        --base)      SCAN_APP=0; SCAN_BASE=1 ;;
        --all)       SCAN_APP=1; SCAN_BASE=1 ;;
        --image)
            [ -z "${2:-}" ] && { echo "Error: --image requires a name argument"; exit 1; }
            SINGLE_IMAGE="$2"; shift ;;
        --image-ref)
            [ -z "${2:-}" ] && { echo "Error: --image-ref requires an image reference argument"; exit 1; }
            IMAGE_REF="$2"; shift ;;
        --no-json)   KEEP_JSON=0 ;;
        --help)      usage ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
    shift
done

# -------------------------------
# Helper: ensure image exists locally
# -------------------------------

ensure_image() {
    local image="$1"

    if docker image inspect "$image" >/dev/null 2>&1; then
        echo "  Image already exists locally"
        return 0
    fi

    echo "  Pulling image..."
    if ! docker pull "$image" 2>&1; then
        echo "  Pull failed"
        return 1
    fi
}

# -------------------------------
# Scan function
# -------------------------------

scan_image () {
    local repo="$1"
    local category="$2"
    local output_dir="$3"
    local image="$ORG/$repo"

    CURRENT_IMAGE=$(( CURRENT_IMAGE + 1 ))
    echo "[$CURRENT_IMAGE/$IMAGE_COUNT] Scanning $repo..."

    if ! ensure_image "$image"; then
        echo "  FAILED to pull $repo"
        echo "$repo ($category): Pull failed or access denied" >> "$SUMMARY_FILE"
        echo >> "$SUMMARY_FILE"
        echo "--------------------------------------------------"
        return
    fi

    # Capture image digest for reproducibility
    local digest
    digest=$(docker inspect --format='{{index .RepoDigests 0}}' "$image" 2>/dev/null || echo "unknown")

    local report_file="$output_dir/json/$repo-grype-report.json"

    grype "$image" -o json > "$report_file"

    # Single jq call to extract all severity counts
    local counts
    counts=$(jq -r '
      [(.matches // [])[].vulnerability.severity] |
      [
        (map(select(.=="Critical")) | length),
        (map(select(.=="High"))     | length),
        (map(select(.=="Medium"))   | length),
        (map(select(.=="Low"))      | length),
        length
      ] | join("\t")
    ' "$report_file")

    local critical high medium low total
    read -r critical high medium low total <<< "$counts"

    # Generate human-readable markdown report
    local readable_report="$output_dir/reports/$repo-report.md"
    {
      echo "## Grype Vulnerability Scan - $repo"
      echo ""
      echo "**Image:** \`$image\`"
      echo "**Digest:** \`$digest\`"
      echo "**Category:** $category"
      echo "**Scan Date:** $(date)"
      echo ""
      if [ "$total" -gt 0 ]; then
        echo "### Vulnerabilities Found: $total"
        echo ""
        echo "| Package | CVE | Severity | Installed Version | Fixed Version |"
        echo "|---------|-----|----------|-------------------|---------------|"
        jq -r '
          [(.matches // [])[] | {
            name: .artifact.name,
            id: .vulnerability.id,
            severity: .vulnerability.severity,
            version: .artifact.version,
            fix: (.vulnerability.fix.versions[0] // "N/A")
          }] | unique_by(.id, .name) |
          sort_by(.severity == "Low", .severity == "Medium", .severity == "High", .severity == "Critical") |
          reverse[] |
          "| \(.name) | \(.id) | \(.severity) | \(.version) | \(.fix) |"
        ' "$report_file"
      else
        echo "### No Vulnerabilities Found"
      fi
    } > "$readable_report"

    # Clean up JSON if requested
    if [ "$KEEP_JSON" -eq 0 ]; then
        rm -f "$report_file"
    fi

    echo "  $repo scanned successfully"

    # Build status indicator
    local status=""
    if [ "$critical" -gt 0 ]; then
        status="🚨"
    elif [ "$high" -gt 3 ]; then
        status="⚠️"
    fi

    {
      echo "$repo ($category): $status"
      echo "  Digest:   $digest"
      echo "  Critical: $critical"
      echo "  High:     $high"
      echo "  Medium:   $medium"
      echo "  Low:      $low"
      echo
    } >> "$SUMMARY_FILE"

    # Check against configurable fail severity
    if [ "$FAIL_SEVERITY" = "Critical" ] && [ "$critical" -gt 0 ]; then
        CRITICAL_FOUND=1
        echo "  CRITICAL vulnerabilities found in $repo"
    elif [ "$FAIL_SEVERITY" = "High" ] && [ $(( critical + high )) -gt 0 ]; then
        CRITICAL_FOUND=1
        echo "  HIGH+ vulnerabilities found in $repo"
    fi

    echo "--------------------------------------------------"
}

# -------------------------------
# Single image scan (--image or --image-ref)
# -------------------------------

if [ -n "$SINGLE_IMAGE" ] || [ -n "$IMAGE_REF" ]; then
    # Determine the image reference and category
    if [ -n "$SINGLE_IMAGE" ]; then
        # Look up the image in APP_IMAGES first, then BASE_IMAGES
        FOUND_CATEGORY=""
        for repo in "${APP_IMAGES[@]}"; do
            if [ "$repo" = "$SINGLE_IMAGE" ]; then
                FOUND_CATEGORY="application"
                break
            fi
        done
        if [ -z "$FOUND_CATEGORY" ]; then
            for repo in "${BASE_IMAGES[@]}"; do
                if [ "$repo" = "$SINGLE_IMAGE" ]; then
                    FOUND_CATEGORY="base"
                    break
                fi
            done
        fi
        if [ -z "$FOUND_CATEGORY" ]; then
            echo "Error: '$SINGLE_IMAGE' not found in APP_IMAGES or BASE_IMAGES."
            echo "Available app images:  ${APP_IMAGES[*]}"
            echo "Available base images: ${BASE_IMAGES[*]}"
            echo ""
            echo "Use --image-ref to scan an arbitrary image reference."
            exit 1
        fi

        IMAGE_COUNT=1
        mkdir -p "$SCAN_DIR"
        if [ "$FOUND_CATEGORY" = "application" ]; then
            mkdir -p "$SCAN_DIR/app-images/json" "$SCAN_DIR/app-images/reports"
            OUTPUT_DIR="$SCAN_DIR/app-images"
        else
            mkdir -p "$SCAN_DIR/base-images/json" "$SCAN_DIR/base-images/reports"
            OUTPUT_DIR="$SCAN_DIR/base-images"
        fi

        {
          echo "Grype Vulnerability Scan Summary"
          echo "Organization    : $ORG_NAME"
          echo "Scan Date       : $(date)"
          echo "Fail Severity   : $FAIL_SEVERITY"
          echo "Image           : $SINGLE_IMAGE"
          echo "=================================================="
          echo
        } > "$SUMMARY_FILE"

        scan_image "$SINGLE_IMAGE" "$FOUND_CATEGORY" "$OUTPUT_DIR"

    else
        # --image-ref: scan an arbitrary full image reference
        # Derive a short name from the ref for file naming
        REPO_NAME=$(echo "$IMAGE_REF" | sed 's|.*/||; s|:.*||')
        IMAGE_COUNT=1
        mkdir -p "$SCAN_DIR/custom/json" "$SCAN_DIR/custom/reports"

        {
          echo "Grype Vulnerability Scan Summary"
          echo "Scan Date       : $(date)"
          echo "Fail Severity   : $FAIL_SEVERITY"
          echo "Image Ref       : $IMAGE_REF"
          echo "=================================================="
          echo
        } > "$SUMMARY_FILE"

        # Inline scan for arbitrary image (bypasses ORG prefix)
        CURRENT_IMAGE=1
        echo "[1/1] Scanning $IMAGE_REF..."

        if ! ensure_image "$IMAGE_REF"; then
            echo "  FAILED to pull $IMAGE_REF"
            echo "$IMAGE_REF: Pull failed or access denied" >> "$SUMMARY_FILE"
            echo "==================================================" >> "$SUMMARY_FILE"
            exit 1
        fi

        local_digest=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE_REF" 2>/dev/null || echo "unknown")
        report_file="$SCAN_DIR/custom/json/$REPO_NAME-grype-report.json"

        grype "$IMAGE_REF" -o json > "$report_file"

        counts=$(jq -r '
          [(.matches // [])[].vulnerability.severity] |
          [
            (map(select(.=="Critical")) | length),
            (map(select(.=="High"))     | length),
            (map(select(.=="Medium"))   | length),
            (map(select(.=="Low"))      | length),
            length
          ] | join("\t")
        ' "$report_file")

        read -r critical high medium low total <<< "$counts"

        readable_report="$SCAN_DIR/custom/reports/$REPO_NAME-report.md"
        {
          echo "## Grype Vulnerability Scan - $IMAGE_REF"
          echo ""
          echo "**Image:** \`$IMAGE_REF\`"
          echo "**Digest:** \`$local_digest\`"
          echo "**Category:** custom"
          echo "**Scan Date:** $(date)"
          echo ""
          if [ "$total" -gt 0 ]; then
            echo "### Vulnerabilities Found: $total"
            echo ""
            echo "| Package | CVE | Severity | Installed Version | Fixed Version |"
            echo "|---------|-----|----------|-------------------|---------------|"
            jq -r '
              [(.matches // [])[] | {
                name: .artifact.name,
                id: .vulnerability.id,
                severity: .vulnerability.severity,
                version: .artifact.version,
                fix: (.vulnerability.fix.versions[0] // "N/A")
              }] | unique_by(.id, .name) |
              sort_by(.severity == "Low", .severity == "Medium", .severity == "High", .severity == "Critical") |
              reverse[] |
              "| \(.name) | \(.id) | \(.severity) | \(.version) | \(.fix) |"
            ' "$report_file"
          else
            echo "### No Vulnerabilities Found"
          fi
        } > "$readable_report"

        if [ "$KEEP_JSON" -eq 0 ]; then
            rm -f "$report_file"
        fi

        echo "  $IMAGE_REF scanned successfully"

        status=""
        [ "$critical" -gt 0 ] && status="🚨"
        [ -z "$status" ] && [ "$high" -gt 3 ] && status="⚠️"

        {
          echo "$IMAGE_REF (custom): $status"
          echo "  Digest:   $local_digest"
          echo "  Critical: $critical"
          echo "  High:     $high"
          echo "  Medium:   $medium"
          echo "  Low:      $low"
          echo
        } >> "$SUMMARY_FILE"

        if [ "$FAIL_SEVERITY" = "Critical" ] && [ "$critical" -gt 0 ]; then
            CRITICAL_FOUND=1
        elif [ "$FAIL_SEVERITY" = "High" ] && [ $(( critical + high )) -gt 0 ]; then
            CRITICAL_FOUND=1
        fi
    fi

    # Final result for single-image modes
    echo "==================================================" >> "$SUMMARY_FILE"
    if [ "$CRITICAL_FOUND" -eq 1 ]; then
        echo "$FAIL_SEVERITY+ vulnerabilities detected!" >> "$SUMMARY_FILE"
        echo "$FAIL_SEVERITY+ vulnerabilities detected"
        echo "See $SUMMARY_FILE for details"
        exit 1
    else
        echo "No $FAIL_SEVERITY+ vulnerabilities found" >> "$SUMMARY_FILE"
        echo "Scan complete - no $FAIL_SEVERITY+ vulnerabilities detected"
        echo "Summary written to $SUMMARY_FILE"
        exit 0
    fi
fi

# -------------------------------
# Interactive prompt (if no CLI args)
# -------------------------------

if [ -z "$SCAN_APP" ] || [ -z "$SCAN_BASE" ]; then
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
fi

# -------------------------------
# Calculate total image count
# -------------------------------

[ "$SCAN_APP" -eq 1 ] && IMAGE_COUNT=$(( IMAGE_COUNT + ${#APP_IMAGES[@]} ))
[ "$SCAN_BASE" -eq 1 ] && IMAGE_COUNT=$(( IMAGE_COUNT + ${#BASE_IMAGES[@]} ))

# -------------------------------
# Create output directories
# -------------------------------

mkdir -p "$SCAN_DIR"
if [ "$SCAN_APP" -eq 1 ]; then
    mkdir -p "$SCAN_DIR/app-images/json" "$SCAN_DIR/app-images/reports"
fi
if [ "$SCAN_BASE" -eq 1 ]; then
    mkdir -p "$SCAN_DIR/base-images/json" "$SCAN_DIR/base-images/reports"
fi

# -------------------------------
# Summary header
# -------------------------------

{
  echo "Grype Vulnerability Scan Summary"
  echo "Organization    : $ORG_NAME"
  echo "Scan Date       : $(date)"
  echo "Fail Severity   : $FAIL_SEVERITY"
  echo "=================================================="
  echo
} > "$SUMMARY_FILE"

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
    echo "$FAIL_SEVERITY+ vulnerabilities detected!" >> "$SUMMARY_FILE"
    echo "$FAIL_SEVERITY+ vulnerabilities detected in one or more images"
    echo "See $SUMMARY_FILE for details"
    exit 1
else
    echo "No $FAIL_SEVERITY+ vulnerabilities found" >> "$SUMMARY_FILE"
    echo "Scan complete - no $FAIL_SEVERITY+ vulnerabilities detected"
    echo "Summary written to $SUMMARY_FILE"
    exit 0
fi