#!/bin/bash
################################################################################
# macOS-GitExec.sh (Bootstrap)
# Version: 1.0.0
#
# Ultra-minimal bootstrap script for GitExec framework
# Downloads, verifies, and sources the GitExec core library
# ALL business logic is in the library - this just bootstraps it
#
# Copyright (C) 2026 Peet, Inc.
# Licensed under GPLv2
################################################################################

set -e

# ====== CONFIGURATION ======
# Set your GitHub organization/username and repo
GITHUB_ORG="YOUR_GITHUB_ORG"
GITHUB_REPO="GitExec"
GITHUB_VERSION="main"

# ====== RMM VARIABLES ======
# Set these in your RMM platform before the script runs.
#
# REQUIRED (choose one):
#   scriptUrl           Full GitHub URL to the script to execute
#                       Formats: github.com/.../blob/... or raw.githubusercontent.com/...
#
#   OR both of these:
#   scriptUrlBase       Base URL path (e.g., https://github.com/org/repo/blob/main/scripts/macOS)
#   scriptName          Script filename (e.g., my-script.sh)
#
# OPTIONAL:
#   runAsUser           "true" = run as each logged-in user, "false" = run as root (default: "false")
#   useAPI              "true" = use GitHub API (bypasses CDN cache) (default: "false")
#   runAsUserTimeout    Seconds to wait for user scripts (default: 600)
#   loggingMode         "None", "FrameworkOnly", or "Full" (default: "Full")
#   logRetentionDays    Days to retain log files (default: 30)

# ====== RUNTIME (don't edit below) ======
# Project version (for User-Agent)
PROJECT_VERSION="1.0.0"

# Environment variables override configuration above
GITEXEC_ORG="${GITEXEC_ORG:-$GITHUB_ORG}"
GITEXEC_REPO="${GITEXEC_REPO:-$GITHUB_REPO}"
GITEXEC_VERSION="${GITEXEC_VERSION:-$GITHUB_VERSION}"

# ====== THIN BOOTSTRAP FUNCTIONS ======
# FROZEN: Only update if cryptographically necessary

# Minimal GitHub PAT retrieval
thin_get_github_pat() {
    local pat
    pat=$(security find-generic-password \
        -s "com.gitexec.github-pat" \
        -a "gitexec_pat" \
        -w /Library/Keychains/System.keychain 2>/dev/null)

    if [[ $? -ne 0 ]] || [[ -z "$pat" ]]; then
        echo "[ERROR] No PAT found." >&2
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
BASE_URL="https://raw.githubusercontent.com/$GITEXEC_ORG/$GITEXEC_REPO/$GITEXEC_VERSION"
LIB="$BASE_URL/_framework/_library/macOS-GitExec-core.sh"
SIG="$BASE_URL/_sig/_framework/_library/macOS-GitExec-core.sh.sig"

# SECURITY: Create temp files with restrictive permissions using mktemp
T=$(mktemp) || {
    echo "[ERROR] Failed to create temp file" >&2
    exit 1
}
T_SIG=$(mktemp) || {
    rm -f "$T"
    echo "[ERROR] Failed to create temp signature file" >&2
    exit 1
}
chmod 600 "$T" "$T_SIG"
trap "rm -f '$T' '$T_SIG'" EXIT

# Download library with authentication
curl -sSL \
    -H "Authorization: token $GITHUB_PAT" \
    -H "User-Agent: GitExec/$PROJECT_VERSION" \
    "$LIB" -o "$T" 2>/dev/null || {
    echo "[ERROR] Library download failed from: $LIB" >&2
    exit 1
}

# Download signature with authentication
curl -sSL \
    -H "Authorization: token $GITHUB_PAT" \
    -H "User-Agent: GitExec/$PROJECT_VERSION" \
    "$SIG" -o "$T_SIG" 2>/dev/null || {
    echo "[ERROR] Signature download failed from: $SIG" >&2
    exit 1
}

# SECURITY: Clear PAT from memory immediately after downloads complete
GITHUB_PAT=""
unset GITHUB_PAT

# Verify library signature
thin_verify "$T" "$T_SIG" || {
    echo "[ERROR] Invalid library signature" >&2
    exit 1
}

# Source library and run
source "$T"
gitexec_init "$@"