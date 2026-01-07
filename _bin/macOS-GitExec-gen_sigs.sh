#!/bin/bash

################################################################################
# GitExec-gen_sigs.sh
#
# SYNOPSIS
#   Recursively generates RSA signatures for all GitExec scripts in the repository
#
# DESCRIPTION
#   This script scans all files in the directory where it's located (and
#   subdirectories) and creates RSA .sig files using the private key stored
#   in macOS Keychain.
#
# REQUIREMENTS
#   - openssl (for RSA signing)
#   - RSA private key stored in macOS Keychain (use GitExec-gen_rsa_keys.sh)
#
# OUTPUT
#   - .sig files for each script file
#   - Signatures saved in _sig/ folder (mirrors repository structure)
#
# NOTES
#   Version: 1.0.0
#   Project: GitExec
#   Last Updated: 2025-10-21
#
# LICENSE
#   Copyright (C) 2026 Peet, Inc.
#   Licensed under GPLv2
################################################################################

set -e

# Color codes (define early for help function)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Function to show help
show_help() {
    cat << EOF
$(echo -e "${CYAN}GitExec Signature Generator v2.0.2${NC}")

$(echo -e "${YELLOW}SYNOPSIS${NC}")
  Generate RSA signatures for all scripts in the repository

$(echo -e "${YELLOW}USAGE${NC}")
  ./GitExec-gen_sigs.sh [OPTIONS]

$(echo -e "${YELLOW}OPTIONS${NC}")
  -h, --help        Show this help message
  -y, --yes         Automatically sign files without prompting
  -f, --force       Force re-signing of all files (even valid signatures)
  -c, --check       Check signature status without signing
  -q, --quiet       Minimal output (status + files only)
  -s, --silent      Silent mode (no output except errors)
  --key SERVICE     Use alternate key service (default: GitExec_RSA)
  --scripts-dir DIR Scripts directory to sign (default: scripts)

$(echo -e "${YELLOW}EXAMPLES${NC}")
  # Normal operation (interactive)
  ./GitExec-gen_sigs.sh

  # Automation - sign what needs signing without prompting
  ./GitExec-gen_sigs.sh --yes

  # Force re-sign everything without prompting
  ./GitExec-gen_sigs.sh --force

  # Check status only, don't sign
  ./GitExec-gen_sigs.sh --check

  # Quiet mode (status + files only)
  ./GitExec-gen_sigs.sh -q
  ./GitExec-gen_sigs.sh --quiet

  # Silent automation
  ./GitExec-gen_sigs.sh -y -s
  ./GitExec-gen_sigs.sh --yes --silent

  # Use custom key service
  KEY_SERVICE=MyCustomKey ./GitExec-gen_sigs.sh

$(echo -e "${YELLOW}FLAGS COMPARISON${NC}")
  (none)    Full verbose output
  --quiet   Status tags + filenames + summary
  --silent  No output except errors
  --check   Report status only, don't sign anything
  --yes     Auto-approve signing without prompting
  --force   Re-sign ALL files (including valid) without prompting

$(echo -e "${YELLOW}FILES${NC}")
  Input:  RMM-Scripts/, _framework/ (scripts to sign)
  Output: _sig/ (signatures), _logs/gen_sigs/ (logs)
  Key:    _key/GitExec_RSA.pub (public key)

$(echo -e "${YELLOW}NOTES${NC}")
  - Verifies existing signatures before signing
  - Only signs files that are new, outdated, or invalid
  - Creates timestamped log in _logs/gen_sigs/
  - Now signs library files in _framework/library/

EOF
    exit 0
}

# Parse command line arguments
FORCE_MODE=false
YES_MODE=false
CHECK_MODE=false
QUIET_MODE=false
SILENT_MODE=false
SCRIPTS_DIR="scripts"

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help|-\?)
            show_help
            ;;
        -y|--yes)
            YES_MODE=true
            shift
            ;;
        -f|--force)
            FORCE_MODE=true
            shift
            ;;
        -c|--check)
            CHECK_MODE=true
            shift
            ;;
        -q|--quiet)
            QUIET_MODE=true
            shift
            ;;
        -s|--silent)
            SILENT_MODE=true
            shift
            ;;
        --key)
            KEY_SERVICE="$2"
            shift 2
            ;;
        --scripts-dir)
            SCRIPTS_DIR="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Error: Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# If script is in _bin folder, repo root is parent; otherwise script IS at repo root
if [[ "$(basename "$SCRIPT_DIR")" == "_bin" ]]; then
    REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
else
    REPO_ROOT="$SCRIPT_DIR"
fi
KEY_SERVICE="${KEY_SERVICE:-GitExec_RSA}"
KEY_ACCOUNT="$USER"
PUBLIC_KEY_FILE="$REPO_ROOT/_key/${KEY_SERVICE}.pub"

# Disable colors in silent mode
if [[ "$SILENT_MODE" == true ]]; then
    RED=''
    GREEN=''
    YELLOW=''
    CYAN=''
    NC=''
fi

# Quiet and silent modes suppress most output
if [[ "$SILENT_MODE" == false ]] && [[ "$QUIET_MODE" == false ]]; then
    echo ""
    echo "=========================================="
    echo "  RSA Signature Generator"
    echo "=========================================="
    echo ""
fi

# Check for openssl
if ! command -v openssl &> /dev/null; then
    echo -e "${RED}Error: openssl is not installed.${NC}"
    exit 1
fi

# Check if public key exists
if [[ ! -f "$PUBLIC_KEY_FILE" ]]; then
    echo -e "${RED}Error: Public key not found${NC}"
    echo ""
    echo "Expected location: $PUBLIC_KEY_FILE"
    echo ""
    echo "Please run GitExec-gen_rsa_keys.sh first to create your signing keys."
    echo ""
    exit 1
fi

if [[ "$SILENT_MODE" == false ]] && [[ "$QUIET_MODE" == false ]]; then
    echo -e "${GREEN}✔ Found public key: _key/${KEY_SERVICE}.pub${NC}"
    echo ""
fi

# Check if private key exists in keychain
if ! security find-generic-password -s "$KEY_SERVICE" -a "$KEY_ACCOUNT" &> /dev/null; then
    echo -e "${RED}Error: RSA private key not found in keychain${NC}"
    echo ""
    echo "Keychain Details:"
    echo "  Service: $KEY_SERVICE"
    echo "  Account: $KEY_ACCOUNT"
    echo ""
    echo "Please run GitExec-gen_rsa_keys.sh first to create your signing keys."
    echo ""
    exit 1
fi

if [[ "$SILENT_MODE" == false ]] && [[ "$QUIET_MODE" == false ]]; then
    echo -e "${GREEN}✔ Found RSA signing key in keychain${NC}"
    echo "  Service: $KEY_SERVICE"
    echo "  Account: $KEY_ACCOUNT"
    echo ""
    echo "Working directory: $REPO_ROOT"
    echo ""
fi

# Counters and arrays for categorization
file_count=0
sig_count=0
skip_count=0
NEW_SIGS=()
OUTDATED_SIGS=()
VALID_SIGS=()
INVALID_SIGS=()

# Function to verify signature
verify_signature() {
    local file="$1"
    local sig_file="$2"
    
    openssl dgst -sha256 -verify "$PUBLIC_KEY_FILE" \
        -signature "$sig_file" "$file" >/dev/null 2>&1
    
    return $?
}

# Function to determine if file should be signed
should_sign_file() {
    local file="$1"
    local relative_path="${file#$REPO_ROOT/}"
    
    # Skip if it's the signature generator itself
    if [[ "$relative_path" == "_bin/GitExec-gen_sigs.sh" ]] || \
       [[ "$(basename "$file")" == "GitExec-gen_sigs.sh" ]]; then
        return 1
    fi
    
    # Sign files in scripts directory
    if [[ "$relative_path" == ${SCRIPTS_DIR}/*.sh ]] || \
       [[ "$relative_path" == ${SCRIPTS_DIR}/*.ps1 ]]; then
        return 0
    fi
    
    # Sign files in _framework/library
    if [[ "$relative_path" == _framework/_library/*.sh ]] || \
       [[ "$relative_path" == _framework/_library/*.psm1 ]]; then
        return 0
    fi
    
   ## Sign files in _framework/thin
   #if [[ "$relative_path" == _framework/thin/*.sh ]] || \
   #   [[ "$relative_path" == _framework/thin/*.ps1 ]]; then
   #    return 0
   #fi
   #
   ## Sign files in _framework/full
   #if [[ "$relative_path" == _framework/full/*.sh ]] || \
   #   [[ "$relative_path" == _framework/full/*.ps1 ]]; then
   #    return 0
   #fi
   #
   ## Sign files in _framework/setup
   #if [[ "$relative_path" == _framework/setup/*.sh ]] || \
   #   [[ "$relative_path" == _framework/setup/*.ps1 ]]; then
   #    return 0
   #fi
    
    # Skip everything else
    return 1
}

# Create temporary file for private key
TEMP_KEY=$(mktemp)
trap "rm -f $TEMP_KEY" EXIT

# Retrieve private key from keychain (returns hex-encoded)
KEY_HEX=$(security find-generic-password -s "$KEY_SERVICE" -a "$KEY_ACCOUNT" -w 2>/dev/null)

if [[ $? -ne 0 ]] || [[ -z "$KEY_HEX" ]]; then
    echo -e "${RED}Error: Failed to retrieve private key from keychain${NC}" >&2
    echo "You may need to allow access in Keychain Access.app" >&2
    exit 1
fi

# Convert hex to actual PEM format
echo "$KEY_HEX" | xxd -r -p > "$TEMP_KEY"

# Verify the key format is valid
if ! openssl rsa -in "$TEMP_KEY" -check -noout >/dev/null 2>&1; then
    echo -e "${RED}Error: Retrieved key is not a valid RSA private key${NC}" >&2
    echo "" >&2
    echo "The key in keychain may be corrupted or in an incorrect format." >&2
    echo "Please regenerate your keys using GitExec-gen_rsa_keys.sh" >&2
    echo "" >&2
    exit 1
fi

if [[ "$SILENT_MODE" == false ]] && [[ "$QUIET_MODE" == false ]]; then
    echo -e "${GREEN}✔ Private key validated${NC}"
fi

# Clean up orphaned signatures
if [[ -d "$REPO_ROOT/_sig" ]] && [[ "$SILENT_MODE" == false ]] && [[ "$QUIET_MODE" == false ]]; then
    echo ""
    echo "Checking for orphaned signatures..."
    orphan_count=0
    while IFS= read -r -d '' sig_file; do
        # Get the relative path from _sig/
        sig_relative="${sig_file#$REPO_ROOT/_sig/}"
        # Remove .sig extension to get source file path
        source_file="$REPO_ROOT/${sig_relative%.sig}"
        
        if [[ ! -f "$source_file" ]]; then
            if [[ "$SILENT_MODE" == false ]] && [[ "$QUIET_MODE" == false ]]; then
                echo -e "${YELLOW}Removing orphaned:${NC} _sig/$sig_relative"
            fi
            rm "$sig_file"
            ((orphan_count++))
        fi
    done < <(find "$REPO_ROOT/_sig" -name "*.sig" -type f -print0 2>/dev/null)
    
    if [[ "$SILENT_MODE" == false ]] && [[ "$QUIET_MODE" == false ]]; then
        if [[ $orphan_count -gt 0 ]]; then
            echo -e "${GREEN}✔${NC} Removed $orphan_count orphaned signature(s)"
        else
            echo -e "${GREEN}✔${NC} No orphaned signatures found"
        fi
    fi
    
    # Clean up empty directories in _sig
    find "$REPO_ROOT/_sig" -type d -empty -delete 2>/dev/null
fi

if [[ "$SILENT_MODE" == false ]] && [[ "$QUIET_MODE" == false ]]; then
    echo ""
fi

# Find all files recursively with exclusions
while IFS= read -r -d '' file; do
    # Get relative path from repo root
    relative_path="${file#$REPO_ROOT/}"
    
    # Check if this file should be signed
    if ! should_sign_file "$file"; then
        ((skip_count++))
        continue
    fi
    
    ((file_count++))
    
    # Create signature path in _sig folder with same structure
    sig_dir="$REPO_ROOT/_sig/$(dirname "$relative_path")"
    sig_file="$sig_dir/$(basename "$file").sig"
    
    # Check if signature exists and compare modification times
    if [[ -f "$sig_file" ]]; then
        script_mtime=$(stat -f %m "$file" 2>/dev/null || stat -c %Y "$file" 2>/dev/null)
        sig_mtime=$(stat -f %m "$sig_file" 2>/dev/null || stat -c %Y "$sig_file" 2>/dev/null)
        
        if [[ $script_mtime -gt $sig_mtime ]]; then
            # Script modified after signature - needs update (don't verify old signature)
            OUTDATED_SIGS+=("$relative_path")
        else
            # Signature should be current - verify it
            if verify_signature "$file" "$sig_file"; then
                VALID_SIGS+=("$relative_path")
            else
                INVALID_SIGS+=("$relative_path")
            fi
        fi
    else
        # No signature exists yet
        NEW_SIGS+=("$relative_path")
    fi
    
done < <(find "$REPO_ROOT" -type f \( -name "*.sh" -o -name "*.ps1" -o -name "*.psm1" \) -print0 | sort -z)

# Phase 2: Report status
if [[ "$QUIET_MODE" == true ]]; then
    # Quiet mode: Simple list format
    for file in "${VALID_SIGS[@]}"; do
        echo "[OK]  $file"
    done
    for file in "${NEW_SIGS[@]}"; do
        echo "[NEW] $file"
    done
    for file in "${OUTDATED_SIGS[@]}"; do
        echo "[OUT] $file"
    done
    for file in "${INVALID_SIGS[@]}"; do
        echo "[BAD] $file"
    done
    
    if [[ ${#VALID_SIGS[@]} -gt 0 ]] || [[ $total_to_sign -gt 0 ]]; then
        echo ""
        echo "${#VALID_SIGS[@]} valid, ${#NEW_SIGS[@]} new, ${#OUTDATED_SIGS[@]} outdated, ${#INVALID_SIGS[@]} invalid"
    fi
elif [[ "$SILENT_MODE" == false ]]; then
    # Verbose mode: Full status report
    echo "=========================================="
    echo "  Signature Status Report"
    echo "=========================================="
    echo "Files scanned:                  $((file_count + skip_count))"
    echo "Files skipped (excluded):       $skip_count"
    echo ""
    echo -e "${GREEN}Files with valid signatures:    ${#VALID_SIGS[@]}${NC}  [OK]"
    echo -e "${CYAN}Files needing new signatures:   ${#NEW_SIGS[@]}${NC}  [NEW]"
    echo -e "${YELLOW}Files with outdated signatures: ${#OUTDATED_SIGS[@]}${NC}  [OUT]"
    if [[ ${#INVALID_SIGS[@]} -gt 0 ]]; then
        echo -e "${RED}Files with invalid signatures:  ${#INVALID_SIGS[@]}${NC}  [BAD] ⚠️"
    else
        echo -e "${GREEN}Files with invalid signatures:  0${NC}  [BAD]"
    fi
    echo "=========================================="
fi

# Calculate total files to sign
total_to_sign=$((${#NEW_SIGS[@]} + ${#OUTDATED_SIGS[@]} + ${#INVALID_SIGS[@]}))

# Prepare log file (always create, even if no changes)
LOG_DIR="$REPO_ROOT/_logs/gen_sigs"
if [[ ! -d "$LOG_DIR" ]]; then
    mkdir -p "$LOG_DIR"
fi

TIMESTAMP=$(date '+%Y-%m-%d_%H%M%S')
LOG_FILE="$LOG_DIR/${TIMESTAMP}.log"

# Write log header
cat > "$LOG_FILE" << EOF
========================================
Signature Generation Log
========================================
Date:       $(date '+%Y-%m-%d %H:%M:%S')
User:       $USER
Repository: $REPO_ROOT

Files Scanned: $((file_count + skip_count))
Files Signed:  $total_to_sign

Signature Verification Results:
  Valid signatures:    ${#VALID_SIGS[@]}
  Invalid signatures:  ${#INVALID_SIGS[@]}
  Outdated signatures: ${#OUTDATED_SIGS[@]}
  New files:           ${#NEW_SIGS[@]}

========================================
Signature Details
========================================

EOF

# Phase 3: Show what will change and prompt
if [[ $total_to_sign -gt 0 ]]; then
    
    # Check mode: just report status and exit
    if [[ "$CHECK_MODE" == true ]]; then
        if [[ "$QUIET_MODE" == true ]]; then
            echo "Check mode: No files were signed"
            echo "Log: _logs/gen_sigs/${TIMESTAMP}.log"
        else
            echo ""
            echo -e "${CYAN}Check mode: Signature status reported above.${NC}"
            echo "No files were signed."
            echo "Log saved to:       _logs/gen_sigs/${TIMESTAMP}.log"
            echo ""
        fi
        
        # Log check mode
        echo "" >> "$LOG_FILE"
        echo "CHECK MODE: No files were signed." >> "$LOG_FILE"
        echo "" >> "$LOG_FILE"
        echo "Files that need signing:" >> "$LOG_FILE"
        for file in "${NEW_SIGS[@]}"; do
            echo "[NEW] $file" >> "$LOG_FILE"
        done
        for file in "${OUTDATED_SIGS[@]}"; do
            echo "[OUT] $file" >> "$LOG_FILE"
        done
        for file in "${INVALID_SIGS[@]}"; do
            echo "[BAD] $file" >> "$LOG_FILE"
        done
        
        exit 0
    fi
    
    if [[ "$QUIET_MODE" == false ]] && [[ "$SILENT_MODE" == false ]]; then
        echo ""
    fi
    
    # Show warning if invalid signatures detected (always show in quiet mode too)
    if [[ ${#INVALID_SIGS[@]} -gt 0 ]] && [[ "$SILENT_MODE" == false ]]; then
        if [[ "$QUIET_MODE" == true ]]; then
            echo ""
            echo "WARNING: ${#INVALID_SIGS[@]} invalid signature(s) detected"
            echo "Will be re-signed"
            echo ""
        else
            echo -e "${RED}⚠️  WARNING: Invalid signatures detected!${NC}"
            echo ""
            echo "The following files have signatures that DO NOT verify:"
            for file in "${INVALID_SIGS[@]}"; do
                echo -e "  ${RED}[BAD]${NC} $file"
            done
            echo ""
            echo "This could indicate:"
            echo "  - Signature file corruption"
            echo "  - Wrong public key being used"
            echo "  - File tampering"
            echo ""
            echo "These files will be re-signed."
            echo ""
        fi
    fi
    
    if [[ "$QUIET_MODE" == true ]]; then
        # Quiet mode: Simple signing message
        if [[ $total_to_sign -gt 0 ]]; then
            echo "Signing $total_to_sign file(s)..."
        fi
    elif [[ "$SILENT_MODE" == false ]]; then
        echo "The following files will be signed:"
        echo ""
        
        for file in "${NEW_SIGS[@]}"; do
            echo -e "  ${CYAN}[NEW]${NC} $file"
        done
        
        for file in "${OUTDATED_SIGS[@]}"; do
            # Get human-readable modification time
            full_path="$REPO_ROOT/$file"
            if [[ "$OSTYPE" == "darwin"* ]]; then
                mtime=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M" "$full_path" 2>/dev/null)
            else
                mtime=$(stat -c "%y" "$full_path" 2>/dev/null | cut -d'.' -f1)
            fi
            echo -e "  ${YELLOW}[OUT]${NC} $file (modified: $mtime)"
        done
        
        for file in "${INVALID_SIGS[@]}"; do
            echo -e "  ${RED}[BAD]${NC} $file (VERIFICATION FAILED - signature invalid!)"
        done
        echo ""
    fi
    
    # Prompt unless force mode or yes mode
    if [[ "$FORCE_MODE" == false ]] && [[ "$YES_MODE" == false ]]; then
        read -p "Continue and sign $total_to_sign file(s)? (yes/no): " -r
        echo ""
        
        if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            echo "Aborted by user."
            
            # Log the abort
            echo "User aborted signing operation." >> "$LOG_FILE"
            echo "" >> "$LOG_FILE"
            echo "Files that would have been signed:" >> "$LOG_FILE"
            for file in "${NEW_SIGS[@]}"; do
                echo "[NEW] $file" >> "$LOG_FILE"
            done
            for file in "${OUTDATED_SIGS[@]}"; do
                echo "[OUT] $file" >> "$LOG_FILE"
            done
            for file in "${INVALID_SIGS[@]}"; do
                echo "[BAD] $file" >> "$LOG_FILE"
            done
            
            exit 0
        fi
    elif [[ "$FORCE_MODE" == true ]]; then
        if [[ "$SILENT_MODE" == false ]] && [[ "$QUIET_MODE" == false ]]; then
            echo "Force mode: Signing $total_to_sign file(s) without prompting..."
            echo ""
        fi
    elif [[ "$YES_MODE" == true ]]; then
        if [[ "$SILENT_MODE" == false ]] && [[ "$QUIET_MODE" == false ]]; then
            echo "Auto-approving: Signing $total_to_sign file(s)..."
            echo ""
        fi
    fi
else
    if [[ "$QUIET_MODE" == true ]]; then
        # Quiet mode: simple message
        echo ""
        echo "All signatures valid"
    elif [[ "$SILENT_MODE" == false ]]; then
        echo ""
        echo -e "${GREEN}✔ All signatures are valid!${NC}"
        echo ""
    fi
    
    # Check mode: just report and exit
    if [[ "$CHECK_MODE" == true ]]; then
        if [[ "$QUIET_MODE" == true ]]; then
            echo "Check mode: No files were signed"
            echo "Log: _logs/gen_sigs/${TIMESTAMP}.log"
        elif [[ "$SILENT_MODE" == false ]]; then
            echo -e "${CYAN}Check mode: All signatures verified successfully.${NC}"
            echo "Log saved to:       _logs/gen_sigs/${TIMESTAMP}.log"
            echo ""
        fi
        
        # Log check mode
        echo "CHECK MODE: All signatures valid." >> "$LOG_FILE"
        
        exit 0
    fi
    
    # Log all valid signatures
    echo "All signatures are valid. No files needed signing." >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    echo "Files with valid signatures:" >> "$LOG_FILE"
    for file in "${VALID_SIGS[@]}"; do
        echo "[OK] $file" >> "$LOG_FILE"
    done
    
    if [[ "$QUIET_MODE" == true ]]; then
        echo "Log: _logs/gen_sigs/${TIMESTAMP}.log"
    elif [[ "$SILENT_MODE" == false ]]; then
        echo "No changes needed. Exiting."
        echo "Log saved to:       _logs/gen_sigs/${TIMESTAMP}.log"
        echo ""
    fi
    exit 0
fi

# Phase 4: Generate signatures
if [[ "$QUIET_MODE" == false ]] && [[ "$SILENT_MODE" == false ]]; then
    echo "Generating signatures..."
    echo ""
fi

# Sign files
signed_count=0

# Process files needing signatures
for relative_path in "${NEW_SIGS[@]}" "${OUTDATED_SIGS[@]}" "${INVALID_SIGS[@]}"; do
    file="$REPO_ROOT/$relative_path"
    
    # Create signature directory if needed
    sig_dir="$REPO_ROOT/_sig/$(dirname "$relative_path")"
    sig_file="$sig_dir/$(basename "$file").sig"
    
    if [[ ! -d "$sig_dir" ]]; then
        mkdir -p "$sig_dir"
    fi
    
    if openssl dgst -sha256 -sign "$TEMP_KEY" -out "$sig_file" "$file" 2>/dev/null; then
        if [[ "$QUIET_MODE" == true ]]; then
            echo "✔ $relative_path"
        elif [[ "$SILENT_MODE" == false ]]; then
            echo -e "${GREEN}✔${NC} $relative_path"
        fi
        ((signed_count++))
        
        # Determine status for log
        if [[ " ${NEW_SIGS[@]} " =~ " ${relative_path} " ]]; then
            echo "[NEW] $relative_path" >> "$LOG_FILE"
        elif [[ " ${INVALID_SIGS[@]} " =~ " ${relative_path} " ]]; then
            echo "[BAD] $relative_path (re-signed after verification failure)" >> "$LOG_FILE"
        else
            echo "[OUT] $relative_path" >> "$LOG_FILE"
        fi
    else
        echo -e "${RED}✗${NC} $relative_path (signing failed)"
        echo "[ERR] $relative_path (signing failed)" >> "$LOG_FILE"
    fi
    
done

# Log valid signatures
if [[ ${#VALID_SIGS[@]} -gt 0 ]]; then
    echo "" >> "$LOG_FILE"
    echo "Files with valid signatures (not re-signed):" >> "$LOG_FILE"
    for file in "${VALID_SIGS[@]}"; do
        echo "[OK] $file" >> "$LOG_FILE"
    done
fi

echo ""
if [[ "$QUIET_MODE" == true ]]; then
    echo ""
    echo "Signed: $signed_count files"
    echo "Log: _logs/gen_sigs/${TIMESTAMP}.log"
elif [[ "$SILENT_MODE" == false ]]; then
    echo "=========================================="
    echo -e "${GREEN}✔ Signature generation complete!${NC}"
    echo "=========================================="
    echo "Files signed:       $signed_count"
    echo "Log saved to:       _logs/gen_sigs/${TIMESTAMP}.log"
    echo ""
    echo -e "${CYAN}Next steps:${NC}"
    echo "  1. Review log file: _logs/gen_sigs/${TIMESTAMP}.log"
    echo "  2. Commit _sig/ folder to git"
    echo "  3. Distribute GitExec_RSA.pub with your scripts"
    echo ""
    echo -e "${YELLOW}Note:${NC} Signature files in _sig/ mirror the directory structure."
    echo "=========================================="
fi

exit 0