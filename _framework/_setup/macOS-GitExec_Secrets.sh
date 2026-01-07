#!/bin/bash

################################################################################
# macOS-set-gitexec_secrets.sh
#
# SYNOPSIS
#   Store GitHub PAT and RSA Public Key securely in macOS System Keychain for GitExec
#
# DESCRIPTION
#   - Stores both the PAT and RSA public key in macOS System Keychain (/Library/Keychains/System.keychain)
#   - Restricts access to root and admin users only
#   - Supports flags: force_update (true/false) and clear_variable (true/false)
#   - Does NOT create per-user keychains. The runner script will handle that
#     if needed for user-context execution.
#   - Both secrets are required and stored/cleared together as a unit
#
# PARAMETERS
#   GitExec_GitHubPAT  - GitHub Personal Access Token (fine-grained, read-only)
#   GitExec_RSA_Pub    - RSA Public Key in PEM format (BEGIN PUBLIC KEY / END PUBLIC KEY)
#   force_update       - "true" to overwrite existing secrets, "false" to skip (default: false)
#   clear_variable     - "true" to delete stored secrets, "false" for normal operation (default: false)
#
# EXAMPLES
#   # Pass as environment variables (RMM style)
#   GitExec_GitHubPAT="github_pat_11AQ...FYFq" \
#   GitExec_RSA_Pub="-----BEGIN PUBLIC KEY-----
#   MIICIjANBg...
#   -----END PUBLIC KEY-----" \
#   ./macOS-set-gitexec_secrets.sh
#
#   # Set variables in script (manual/testing)
#   GitExec_GitHubPAT="github_pat_11AQ...FYFq"
#   GitExec_RSA_Pub="-----BEGIN PUBLIC KEY-----..."
#   ./macOS-set-gitexec_secrets.sh
#
#   # Update existing secrets
#   GitExec_GitHubPAT="github_pat_NEW_TOKEN" \
#   GitExec_RSA_Pub="-----BEGIN PUBLIC KEY-----..." \
#   force_update="true" ./macOS-set-gitexec_secrets.sh
#
#   # Clear/remove stored secrets
#   clear_variable="true" ./macOS-set-gitexec_secrets.sh
#
# REQUIREMENTS
#   - Must be run as root (sudo)
#   - macOS 10.12+ (for security command with system keychain)
#
# HOW TO GET A GITHUB PAT
#   1. Go to: https://github.com/settings/tokens?type=beta
#   2. Click "Generate new token" → "Fine-grained token"
#   3. Token name: "MSP-Scripts-ReadOnly" (or similar)
#   4. Expiration: 90 days (then rotate)
#   5. Repository access: "Only select repositories" → Pick your scripts repo
#   6. Permissions: Repository permissions → Contents: "Read-only"
#   7. Generate token and copy it (starts with "github_pat_")
#   8. Set as environment variable or hardcode below
#
# ROTATING PATS
#   When your token expires (or for security rotation):
#   1. Generate a new PAT following steps above
#   2. Run: GitExec_GitHubPAT="NEW_TOKEN" force_update="true" ./macOS-set-gitexec_secrets.sh
#
# SECURITY NOTE
#   - This script stores both PAT and RSA public key in macOS System Keychain
#   - Only root and admin users can access system keychain items
#   - The PAT should have READ-ONLY access to your scripts repository
#   - The RSA public key is used to verify script signatures
#   - Never commit this script with hardcoded secrets to version control
#
# NOTES
#   Project: GitExec
#   Compatible with: macOS 10.12+, SyncroRMM, other RMM platforms
#
#   Changes in v2.0.1:
#     - Aligned version number with Windows script (was 1.9.0)
#     - Both secrets (PAT and RSA key) are required and managed together
#     - RSA key stored as normalized base64 (no PEM headers)
#     - Supports force_update flag for overwriting existing secrets
#     - Supports clear_variable flag for removing both secrets
#     - Full PEM format validation with base64 decode test
#     - Atomic operations: both secrets installed/cleared together
#     - Cross-platform consistency with Windows implementation
#     - Boolean normalization: converts yes/no, $true/$false to true/false
#     - Standardized boolean values to match execute script (true/false)
#     - Unified logging with log_message() function and timestamps
#     - Consistent log format across all GitExec scripts
#
#   Previous features:
#     - Stores both PAT and RSA public key in macOS System Keychain
#     - Restricts access to root and admin users only
#     - Validates GitHub PAT format (fine-grained and classic tokens)
#     - Validates RSA public key PEM format
#     - Handles both multi-line and single-line input (SyncroRMM compatible)
#     - Verification step after storing secrets
#     - Comprehensive error handling and user-friendly messages
#
# LICENSE
#   Copyright (C) 2026 Peet, Inc.
#   Licensed under GPLv2
#   See <https://www.gnu.org/licenses/old-licenses/gpl-2.0.html>
################################################################################

# ====== NORMALIZE BOOLEAN VARIABLES ======
# This must run before configuration to convert yes/no, $true/$false, etc.
normalize_boolean_variables() {
    local var_names=$(compgen -v)

    for var_name in $var_names; do
        # Skip readonly/special variables
        if [[ "$var_name" =~ ^(BASH|EUID|UID|PPID|RANDOM|SECONDS|LINENO|OLDPWD|PWD|SHLVL|_).*$ ]]; then
            continue
        fi

        # Skip our constants
        if [[ "$var_name" =~ ^(KEYCHAIN_|SCRIPT_VERSION|RED|GREEN|YELLOW|CYAN|NC|GitExec_).*$ ]]; then
            continue
        fi

        # Additional validation: only allow alphanumeric variable names
        if [[ ! "$var_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
            continue
        fi

        local var_value="${!var_name}"

        # Convert to lowercase (bash 3.x compatible)
        local var_value_lower=$(echo "$var_value" | tr '[:upper:]' '[:lower:]')

        # SECURITY: Use printf -v for indirect assignment instead of eval
        if [[ "$var_value_lower" =~ ^(\$?true|yes)$ ]]; then
            printf -v "$var_name" '%s' 'true'
        elif [[ "$var_value_lower" =~ ^(\$?false|no)$ ]]; then
            printf -v "$var_name" '%s' 'false'
        fi
    done
}

# Call normalization before setting defaults
normalize_boolean_variables

# ====== CONFIGURATION ======

# Variables can be set three ways:
# 1. Environment variables (RMM injection): GitExec_GitHubPAT="token" ./script.sh
# 2. Set below for manual use (replace the placeholder)
# 3. Passed via shell before running: GitExec_GitHubPAT="token"; ./script.sh

# MANUAL CONFIGURATION (if not using environment variables or RMM injection):
# Replace the placeholders below with your actual secrets:
if [[ -z "$GitExec_GitHubPAT" ]]; then
    GitExec_GitHubPAT="ONLY_PASTE_YOUR_TOKEN_HERE_TO_HARDCODE"
fi

if [[ -z "$GitExec_RSA_Pub" ]]; then
    GitExec_RSA_Pub="-----BEGIN PUBLIC KEY-----
PASTE_YOUR_RSA_PUBLIC_KEY_HERE
-----END PUBLIC KEY-----"
fi

# Set defaults if not already defined
force_update="${force_update:-false}"
clear_variable="${clear_variable:-false}"

# ====== CONSTANTS ======
KEYCHAIN_SERVICE_PAT="com.gitexec.github-pat"
KEYCHAIN_ACCOUNT_PAT="gitexec_pat"
KEYCHAIN_LABEL_PAT="GitExec GitHub PAT"

KEYCHAIN_SERVICE_RSA="com.gitexec.rsa-public-key"
KEYCHAIN_ACCOUNT_RSA="gitexec_rsa_pub"
KEYCHAIN_LABEL_RSA="GitExec RSA Public Key"

SCRIPT_VERSION="1.0.1"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

################################################################################
# LOGGING FUNCTIONS
################################################################################

log_message() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")

    case "$level" in
        START)
            echo -e "${CYAN}[$timestamp] [START] $message${NC}" >&2
            ;;
        COMPLETE)
            echo -e "${CYAN}[$timestamp] [COMPLETE] $message${NC}" >&2
            ;;
        INFO)
            echo "[$timestamp] [INFO] $message" >&2
            ;;
        OK)
            echo -e "${GREEN}[$timestamp] [OK] $message${NC}" >&2
            ;;
        WARN)
            echo -e "${YELLOW}[$timestamp] [WARN] $message${NC}" >&2
            ;;
        ERROR)
            echo -e "${RED}[$timestamp] [ERROR] $message${NC}" >&2
            ;;
        *)
            echo "[$timestamp] $message" >&2
            ;;
    esac
}

print_header() {
    echo ""
    echo "==============================================="
    echo "  GitExec Secrets Installer"
    echo "  Version ${SCRIPT_VERSION} (macOS)"
    echo "==============================================="
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_message ERROR "This script must be run as root (use sudo)"
        echo ""
        echo "This installer must be run with root privileges to access the system keychain."
        echo ""
        echo "How to run as root:"
        echo "  sudo ./macOS-set-gitexec_secrets.sh"
        echo ""
        echo "For RMM deployment:"
        echo "  - Most RMMs run scripts as root by default"
        echo "  - Ensure your RMM job is configured to run with elevated privileges"
        echo ""
        exit 1
    fi
}

check_keychain_access() {
    if ! command -v security &> /dev/null; then
        log_message ERROR "macOS 'security' command not found"
        echo "This script requires macOS with the security command-line tool."
        exit 1
    fi
    log_message OK "macOS security command available"
}

validate_pat() {
    local pat="$1"

    if [[ -z "$pat" ]]; then
        log_message ERROR "GitHub PAT not provided!"
        echo ""
        echo "The GitExec_GitHubPAT variable must be set before running this script."
        echo ""
        echo "For RMM deployment, ensure your job sets:"
        echo "  GitExec_GitHubPAT='github_pat_YOUR_TOKEN_HERE'"
        echo "  GitExec_RSA_Pub='-----BEGIN PUBLIC KEY-----...'"
        echo ""
        echo "For manual testing:"
        echo "  GitExec_GitHubPAT='github_pat_YOUR_TOKEN_HERE' ./macOS-set-gitexec_secrets.sh"
        echo ""
        echo "Or edit the script and replace the placeholders."
        echo ""
        echo "To clear existing secrets:"
        echo "  clear_variable='true' ./macOS-set-gitexec_secrets.sh"
        echo ""
        exit 1
    fi

    # Validate GitHub PAT format
    # Fine-grained tokens: github_pat_[A-Za-z0-9_]{82}
    # Classic tokens: ghp_[A-Za-z0-9]{36}
    if [[ ! "$pat" =~ ^github_pat_[A-Za-z0-9_]{82}$ ]] && [[ ! "$pat" =~ ^ghp_[A-Za-z0-9]{36}$ ]]; then
        log_message ERROR "Invalid GitHub PAT format!"
        echo ""
        echo "GitHub Personal Access Tokens must match one of these formats:"
        echo "  Fine-grained: github_pat_ followed by 82 characters (letters, numbers, underscore)"
        echo "  Classic:      ghp_ followed by 36 characters (letters, numbers)"
        echo ""
        echo "Your token appears to be: ${pat:0:20}..."
        echo ""
        echo "Common issues:"
        echo "  - Did you forget to replace the placeholder value?"
        echo "  - Did you copy the entire token from GitHub?"
        echo "  - Did you accidentally include extra spaces or quotes?"
        echo ""
        echo "To generate a valid GitHub PAT:"
        echo "  1. Go to: https://github.com/settings/tokens?type=beta"
        echo "  2. Generate a fine-grained token with Contents: Read-only"
        echo "  3. Copy the complete token (starts with 'github_pat_')"
        echo ""
        exit 1
    fi

    log_message OK "PAT format validated"
}

validate_rsa_pub() {
    local key="$1"

    if [[ -z "$key" ]]; then
        log_message ERROR "RSA Public Key not provided!"
        echo ""
        echo "The GitExec_RSA_Pub variable must be set before running this script."
        echo ""
        echo "Both GitExec_GitHubPAT and GitExec_RSA_Pub are required."
        echo ""
        exit 1
    fi

    # Check for required markers
    if [[ ! "$key" =~ "-----BEGIN PUBLIC KEY-----" ]] || \
       [[ ! "$key" =~ "-----END PUBLIC KEY-----" ]]; then
        log_message ERROR "Invalid RSA public key format!"
        echo ""
        echo "RSA public key must be in PEM format with markers:"
        echo "  -----BEGIN PUBLIC KEY-----"
        echo "  [base64 encoded key data]"
        echo "  -----END PUBLIC KEY-----"
        echo ""
        echo "Common issues:"
        echo "  - Did you forget to replace the placeholder?"
        echo "  - Did you copy the complete key including BEGIN/END markers?"
        echo "  - Did you use the correct format (not SSH format)?"
        echo ""
        exit 1
    fi

    # Extract base64 content and clean it
    # Handle both proper multi-line format and SyncroMSP single-line format
    local base64_content
    base64_content=$(echo "$key" | \
        sed 's/-----BEGIN PUBLIC KEY-----//g; s/-----END PUBLIC KEY-----//g' | \
        tr -d ' \n\r\t')

    if [[ -z "$base64_content" ]]; then
        log_message ERROR "No base64 content found in RSA public key!"
        exit 1
    fi

    # Validate it's valid base64 by attempting to decode
    if ! echo "$base64_content" | base64 -D >/dev/null 2>&1; then
        log_message ERROR "Invalid base64 content in RSA public key!"
        echo ""
        echo "The key content could not be decoded as valid base64."
        echo "Please verify you copied the complete key correctly."
        echo ""
        exit 1
    fi

    log_message OK "RSA public key format validated and normalized"

    # Return the cleaned base64 content (no PEM headers, no whitespace)
    echo "$base64_content"
}

check_existing_pat() {
    # Check if PAT already exists in system keychain
    if security find-generic-password -s "$KEYCHAIN_SERVICE_PAT" -a "$KEYCHAIN_ACCOUNT_PAT" /Library/Keychains/System.keychain &> /dev/null; then
        return 0  # Exists
    else
        return 1  # Does not exist
    fi
}

check_existing_rsa() {
    # Check if RSA key already exists in system keychain
    if security find-generic-password -s "$KEYCHAIN_SERVICE_RSA" -a "$KEYCHAIN_ACCOUNT_RSA" /Library/Keychains/System.keychain &> /dev/null; then
        return 0  # Exists
    else
        return 1  # Does not exist
    fi
}

get_existing_pat_info() {
    # Get modification date of existing PAT from system keychain
    local info
    info=$(security find-generic-password -s "$KEYCHAIN_SERVICE_PAT" -a "$KEYCHAIN_ACCOUNT_PAT" /Library/Keychains/System.keychain 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        echo "$info" | grep "mdat" | cut -d'"' -f4
    else
        echo "Unknown"
    fi
}

get_existing_rsa_info() {
    # Get modification date of existing RSA key from system keychain
    local info
    info=$(security find-generic-password -s "$KEYCHAIN_SERVICE_RSA" -a "$KEYCHAIN_ACCOUNT_RSA" /Library/Keychains/System.keychain 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        echo "$info" | grep "mdat" | cut -d'"' -f4
    else
        echo "Unknown"
    fi
}

clear_secrets() {
    log_message INFO "Operation: CLEAR existing secrets"
    echo ""

    local cleared_any=false

    # Clear PAT
    if check_existing_pat; then
        local mod_date
        mod_date=$(get_existing_pat_info)

        security delete-generic-password -s "$KEYCHAIN_SERVICE_PAT" -a "$KEYCHAIN_ACCOUNT_PAT" /Library/Keychains/System.keychain &> /dev/null

        if [[ $? -eq 0 ]]; then
            log_message OK "Cleared GitHub PAT"
            echo "  Service: $KEYCHAIN_SERVICE_PAT"
            echo "  Account: $KEYCHAIN_ACCOUNT_PAT"
            if [[ "$mod_date" != "Unknown" ]]; then
                echo "  Was last modified: $mod_date"
            fi
            cleared_any=true
        else
            log_message ERROR "Failed to clear PAT from keychain"
            exit 1
        fi
    else
        log_message INFO "No GitHub PAT found to clear"
    fi

    echo ""

    # Clear RSA key
    if check_existing_rsa; then
        local mod_date
        mod_date=$(get_existing_rsa_info)

        security delete-generic-password -s "$KEYCHAIN_SERVICE_RSA" -a "$KEYCHAIN_ACCOUNT_RSA" /Library/Keychains/System.keychain &> /dev/null

        if [[ $? -eq 0 ]]; then
            log_message OK "Cleared RSA Public Key"
            echo "  Service: $KEYCHAIN_SERVICE_RSA"
            echo "  Account: $KEYCHAIN_ACCOUNT_RSA"
            if [[ "$mod_date" != "Unknown" ]]; then
                echo "  Was last modified: $mod_date"
            fi
            cleared_any=true
        else
            log_message ERROR "Failed to clear RSA key from keychain"
            exit 1
        fi
    else
        log_message INFO "No RSA Public Key found to clear"
    fi

    echo ""

    if [[ "$cleared_any" == false ]]; then
        log_message INFO "No secrets found in keychain"
    else
        log_message OK "Secrets cleared successfully"
    fi
}

install_secrets() {
    local pat="$1"
    local rsa_key="$2"
    local is_update=false
    
    # Validate and normalize RSA key to base64
    local rsa_base64
    rsa_base64=$(validate_rsa_pub "$rsa_key")
    
    # Check if secrets already exist
    local pat_exists=false
    local rsa_exists=false
    
    if check_existing_pat; then
        pat_exists=true
    fi
    
    if check_existing_rsa; then
        rsa_exists=true
    fi
    
    if [[ "$pat_exists" == true ]] || [[ "$rsa_exists" == true ]]; then
        is_update=true

        if [[ "$force_update" != "true" ]]; then
            echo ""
            echo "==============================================="
            log_message WARN "Secrets Already Exist"
            echo "==============================================="

            if [[ "$pat_exists" == true ]]; then
                echo "GitHub PAT is configured:"
                echo "  Service: $KEYCHAIN_SERVICE_PAT"
                echo "  Account: $KEYCHAIN_ACCOUNT_PAT"
                local mod_date
                mod_date=$(get_existing_pat_info)
                if [[ "$mod_date" != "Unknown" ]]; then
                    echo "  Last modified: $mod_date"
                fi
                echo ""
            fi

            if [[ "$rsa_exists" == true ]]; then
                echo "RSA Public Key is configured:"
                echo "  Service: $KEYCHAIN_SERVICE_RSA"
                echo "  Account: $KEYCHAIN_ACCOUNT_RSA"
                local mod_date
                mod_date=$(get_existing_rsa_info)
                if [[ "$mod_date" != "Unknown" ]]; then
                    echo "  Last modified: $mod_date"
                fi
                echo ""
            fi

            echo -e "${CYAN}To overwrite, set:${NC}"
            echo "  force_update='true'"
            echo "==============================================="
            return 0
        fi

        echo ""
        log_message WARN "UPDATING existing secrets (force_update='true')"
        echo ""
        
        # Delete existing items before adding new ones
        if [[ "$pat_exists" == true ]]; then
            security delete-generic-password -s "$KEYCHAIN_SERVICE_PAT" -a "$KEYCHAIN_ACCOUNT_PAT" /Library/Keychains/System.keychain &> /dev/null
        fi
        
        if [[ "$rsa_exists" == true ]]; then
            security delete-generic-password -s "$KEYCHAIN_SERVICE_RSA" -a "$KEYCHAIN_ACCOUNT_RSA" /Library/Keychains/System.keychain &> /dev/null
        fi
    fi
    
    # Install GitHub PAT
    log_message INFO "Storing GitHub PAT in System Keychain..."

    security add-generic-password \
        -s "$KEYCHAIN_SERVICE_PAT" \
        -a "$KEYCHAIN_ACCOUNT_PAT" \
        -l "$KEYCHAIN_LABEL_PAT" \
        -w "$pat" \
        -A \
        /Library/Keychains/System.keychain &> /dev/null

    if [[ $? -ne 0 ]]; then
        log_message ERROR "Failed to store PAT in system keychain"
        exit 1
    fi

    log_message OK "Saved GitHub PAT to system keychain"

    # Verify PAT
    local retrieved_pat
    retrieved_pat=$(security find-generic-password -s "$KEYCHAIN_SERVICE_PAT" -a "$KEYCHAIN_ACCOUNT_PAT" -w /Library/Keychains/System.keychain 2>/dev/null)

    if [[ $? -eq 0 ]] && [[ "$retrieved_pat" == "$pat" ]]; then
        log_message OK "GitHub PAT verification successful"
    else
        log_message ERROR "GitHub PAT verification failed"
        security delete-generic-password -s "$KEYCHAIN_SERVICE_PAT" -a "$KEYCHAIN_ACCOUNT_PAT" /Library/Keychains/System.keychain &> /dev/null
        exit 1
    fi

    echo ""

    # Install RSA Public Key
    log_message INFO "Storing RSA Public Key in System Keychain..."

    security add-generic-password \
        -s "$KEYCHAIN_SERVICE_RSA" \
        -a "$KEYCHAIN_ACCOUNT_RSA" \
        -l "$KEYCHAIN_LABEL_RSA" \
        -w "$rsa_base64" \
        -A \
        /Library/Keychains/System.keychain &> /dev/null

    if [[ $? -ne 0 ]]; then
        log_message ERROR "Failed to store RSA key in system keychain"
        # Clean up PAT since we failed
        security delete-generic-password -s "$KEYCHAIN_SERVICE_PAT" -a "$KEYCHAIN_ACCOUNT_PAT" /Library/Keychains/System.keychain &> /dev/null
        exit 1
    fi

    log_message OK "Saved RSA Public Key to system keychain (stored as base64)"

    # Verify RSA key
    local retrieved_key
    retrieved_key=$(security find-generic-password -s "$KEYCHAIN_SERVICE_RSA" -a "$KEYCHAIN_ACCOUNT_RSA" -w /Library/Keychains/System.keychain 2>/dev/null)

    if [[ $? -eq 0 ]] && [[ "$retrieved_key" == "$rsa_base64" ]]; then
        log_message OK "RSA Public Key verification successful"
    else
        log_message ERROR "RSA Public Key verification failed"
        # Clean up both secrets
        security delete-generic-password -s "$KEYCHAIN_SERVICE_PAT" -a "$KEYCHAIN_ACCOUNT_PAT" /Library/Keychains/System.keychain &> /dev/null
        security delete-generic-password -s "$KEYCHAIN_SERVICE_RSA" -a "$KEYCHAIN_ACCOUNT_RSA" /Library/Keychains/System.keychain &> /dev/null
        exit 1
    fi

    # Display success summary
    echo ""
    echo "==============================================="
    log_message OK "GitExec Secrets Setup Complete!"
    echo "==============================================="
    
    if [[ "$is_update" == true ]]; then
        echo "Status:       Updated [OK]"
    else
        echo "Status:       Ready to use [OK]"
    fi
    echo ""
    echo -e "${CYAN}GitHub PAT:${NC}"
    echo "  Service:    $KEYCHAIN_SERVICE_PAT"
    echo "  Account:    $KEYCHAIN_ACCOUNT_PAT"
    echo "  Label:      $KEYCHAIN_LABEL_PAT"
    echo ""
    echo -e "${CYAN}RSA Public Key:${NC}"
    echo "  Service:    $KEYCHAIN_SERVICE_RSA"
    echo "  Account:    $KEYCHAIN_ACCOUNT_RSA"
    echo "  Label:      $KEYCHAIN_LABEL_RSA"
    echo "  Format:     Base64 (normalized)"
    echo ""
    echo -e "${CYAN}Storage:${NC}"
    echo "  Keychain:   /Library/Keychains/System.keychain"
    echo "  Access:     Root and admin users only"
    echo "  Scope:      System-wide (all root/admin processes)"
    echo ""
    echo -e "${CYAN}Retrieval:${NC}"
    echo "  The RSA key is stored as base64 without PEM headers."
    echo "  To retrieve as proper PEM format:"
    echo "    base64_key=\$(security find-generic-password -s \"$KEYCHAIN_SERVICE_RSA\" -a \"$KEYCHAIN_ACCOUNT_RSA\" -w /Library/Keychains/System.keychain)"
    echo "    echo \"-----BEGIN PUBLIC KEY-----\""
    echo "    echo \"\$base64_key\" | fold -w 64"
    echo "    echo \"-----END PUBLIC KEY-----\""
    echo ""
    echo -e "${CYAN}Next Steps:${NC}"
    echo "  1. Deploy GitExec runner script via your RMM"
    echo "  2. Set script URL to your GitHub repository"
    echo "  3. GitExec will use these secrets for secure execution"
    echo "==============================================="
}

################################################################################
# MAIN EXECUTION
################################################################################

print_header

# Check execution context
log_message INFO "Checking execution context..."
check_root
log_message OK "Running as root"
echo ""

# Check macOS security command
log_message INFO "Checking macOS security tools..."
check_keychain_access
echo ""

# Handle clear operation
if [[ "$clear_variable" == "true" ]]; then
    clear_secrets
    exit 0
fi

# Normal install/update operation
log_message INFO "Operation: SAVE GitExec Secrets"
echo ""

# Validate PAT
validate_pat "$GitExec_GitHubPAT"
echo ""

# RSA key will be validated inside install_secrets function
# Install both secrets
install_secrets "$GitExec_GitHubPAT" "$GitExec_RSA_Pub"

echo ""
exit 0