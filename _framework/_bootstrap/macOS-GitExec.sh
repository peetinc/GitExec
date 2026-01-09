#!/bin/bash
################################################################################
# macOS-GitExec.sh (Bootstrap)
#
# Ultra-minimal bootstrap script for GitExec framework
# Downloads, verifies, and sources the GitExec core library
# ALL business logic is in the library - this just bootstraps it
#
# Copyright (C) 2026 Peet, Inc.
# Licensed under GPLv2
################################################################################

set -e

# ====== RMM VARIABLES ======
# Set ALL of these in your RMM platform before the script runs.
#
# REQUIRED:
#   github_Org          Your GitHub organization or username
#   github_Repo         Repository name containing GitExec framework
#   scriptUrl           Full GitHub URL to the script to execute
#                       Formats: github.com/.../blob/... or raw.githubusercontent.com/...
#
#   OR instead of scriptUrl, set both:
#   scriptUrlBase       Base URL path (e.g., https://github.com/org/repo/blob/main/scripts/macOS)
#   scriptName          Script filename (e.g., my-script.sh)
#
# OPTIONAL:
#   github_Branch       Branch or tag (default: main)
#   runAsUser           "true" = run as each logged-in user, "false" = run as root (default: "false")
#   useAPI              "true" = use GitHub API (bypasses CDN cache) (default: "false")
#   runAsUserTimeout    Seconds to wait for user scripts (default: 600)
#   loggingMode         "None", "FrameworkOnly", or "Full" (default: "Full")
#   logRetentionDays    Days to retain log files (default: 30)

# ====== RMM DETECTION & VARIABLE TRANSLATION ======
# Gorelo RMM uses text substitution: $gorelo':'varName → 'value'
if [[ "${BASH_SOURCE[0]}" == /Library/Gorelo/Agent/AppData/Script/* ]]; then
    GITEXEC_RMM="gorelo"
    github_Org=$gorelo:github_Org
    github_Repo=$gorelo:github_Repo
    github_Branch=$gorelo:github_Branch
    scriptUrl=$gorelo:scriptUrl
    scriptUrlBase=$gorelo:scriptUrlBase
    scriptName=$gorelo:scriptName
    runAsUser=$gorelo:runAsUser
    useAPI=$gorelo:useAPI
    runAsUserTimeout=$gorelo:runAsUserTimeout
    loggingMode=$gorelo:loggingMode
    logRetentionDays=$gorelo:logRetentionDays
fi

# ====== RUNTIME (don't edit below) ======
PROJECT_VERSION="1.0.1"

# Debug output function for troubleshooting failures
print_debug_info() {
    echo ""
    echo "[DEBUG] Variables:" >&2
    echo "  GITEXEC_RMM:      ${GITEXEC_RMM:-}" >&2
    echo "  GITEXEC_ORG:      ${GITEXEC_ORG:-}" >&2
    echo "  GITEXEC_REPO:     ${GITEXEC_REPO:-}" >&2
    echo "  GITEXEC_BRANCH:   ${GITEXEC_BRANCH:-}" >&2
    echo "  scriptUrl:        ${scriptUrl:-}" >&2
    echo "  scriptUrlBase:    ${scriptUrlBase:-}" >&2
    echo "  scriptName:       ${scriptName:-}" >&2
    local builtUrl="${scriptUrl:-}"
    [[ -z "$builtUrl" && -n "$scriptUrlBase" && -n "$scriptName" ]] && builtUrl="${scriptUrlBase%/}/$scriptName"
    echo "  builtScriptUrl:   ${builtUrl:-(not set)}" >&2
    echo "  runAsUser:        ${runAsUser:-}" >&2
    echo "  useAPI:           ${useAPI:-}" >&2
    echo "  runAsUserTimeout: ${runAsUserTimeout:-}" >&2
    echo "  loggingMode:      ${loggingMode:-}" >&2
    echo "  logRetentionDays: ${logRetentionDays:-}" >&2
    echo "  LIB:              ${LIB:-}" >&2
    echo "  SIG:              ${SIG:-}" >&2
    [[ -n "${T:-}" ]] && echo "  TempLib:          $T (exists: $(test -f "$T" && echo "yes, size: $(wc -c < "$T")" || echo "no"))" >&2
    [[ -n "${T_SIG:-}" ]] && echo "  TempSig:          $T_SIG (exists: $(test -f "$T_SIG" && echo "yes, size: $(wc -c < "$T_SIG")" || echo "no"))" >&2
}

# Validate required variables
if [[ -z "$github_Org" ]]; then
    echo "[FATAL] github_Org is required but not set. Configure this in your RMM platform." >&2
    print_debug_info
    exit 1
fi
if [[ -z "$github_Repo" ]]; then
    echo "[FATAL] github_Repo is required but not set. Configure this in your RMM platform." >&2
    print_debug_info
    exit 1
fi

# Apply defaults for optional variables
github_Branch="${github_Branch:-main}"

# Set runtime variables
GITEXEC_ORG="$github_Org"
GITEXEC_REPO="$github_Repo"
GITEXEC_BRANCH="$github_Branch"

# ====== THIN BOOTSTRAP FUNCTIONS ======
# FROZEN: Only update if cryptographically necessary

# Minimal GitHub PAT retrieval
thin_get_github_pat() {
    local pat
    if ! pat=$(security find-generic-password \
        -s "com.gitexec.github-pat" \
        -a "gitexec_pat" \
        -w /Library/Keychains/System.keychain 2>/dev/null) || [[ -z "$pat" ]]; then
        echo "[ERROR] No PAT found. Run macOS-GitExec_Secrets.sh first." >&2
        print_debug_info
        exit 1
    fi
    echo "$pat"
}

# Minimal signature verification
thin_verify() {
    local key
    key=$(security find-generic-password \
        -s "com.gitexec.rsa-public-key" \
        -a "gitexec_rsa_pub" \
        -w /Library/Keychains/System.keychain 2>/dev/null) || return 1

    openssl dgst -sha256 -verify <(
        printf '%s\n%s\n%s\n' \
            "-----BEGIN PUBLIC KEY-----" \
            "$(echo "$key" | fold -w 64)" \
            "-----END PUBLIC KEY-----"
    ) -signature "$2" "$1" &>/dev/null
}

# ====== DOWNLOAD AND SOURCE LIBRARY ======
# Get GitHub PAT for authenticated downloads
GITHUB_PAT=$(thin_get_github_pat)

# Build URLs from configuration
BASE_URL="https://raw.githubusercontent.com/$GITEXEC_ORG/$GITEXEC_REPO/$GITEXEC_BRANCH"
LIB="$BASE_URL/_framework/_library/macOS-GitExec-core.sh"
SIG="$BASE_URL/_sig/_framework/_library/macOS-GitExec-core.sh.sig"

# SECURITY: Create temp files with restrictive permissions using mktemp
T=$(mktemp) || {
    echo "[ERROR] Failed to create temp file" >&2
    print_debug_info
    exit 1
}
T_SIG=$(mktemp) || {
    rm -f "$T"
    echo "[ERROR] Failed to create temp signature file" >&2
    print_debug_info
    exit 1
}
chmod 600 "$T" "$T_SIG"
trap "rm -f '$T' '$T_SIG'" EXIT

# Download library with authentication
curl -fsSL \
    -H "Authorization: Bearer $GITHUB_PAT" \
    -H "User-Agent: GitExec/$PROJECT_VERSION" \
    "$LIB" -o "$T" 2>/dev/null || {
    echo "[ERROR] Library download failed from: $LIB" >&2
    print_debug_info
    exit 1
}

# Download signature with authentication
curl -fsSL \
    -H "Authorization: Bearer $GITHUB_PAT" \
    -H "User-Agent: GitExec/$PROJECT_VERSION" \
    "$SIG" -o "$T_SIG" 2>/dev/null || {
    echo "[ERROR] Signature download failed from: $SIG" >&2
    print_debug_info
    exit 1
}

# SECURITY: Clear PAT from memory immediately after downloads complete
GITHUB_PAT=""
unset GITHUB_PAT

# Verify library signature
thin_verify "$T" "$T_SIG" || {
    echo "[ERROR] Invalid library signature" >&2
    print_debug_info
    exit 1
}

# Source library and run
source "$T"
gitexec_init "$@"