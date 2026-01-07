#!/bin/bash

################################################################################
# GitExec-gen_rsa_keys.sh
#
# SYNOPSIS
#   Generates RSA key pair for GitExec script signing and stores private key 
#   in macOS Keychain
#
# DESCRIPTION
#   This script generates a 4096-bit RSA key pair for signing GitExec scripts.
#   - Private key is stored securely in macOS Login Keychain as generic password
#   - Private key backup is encrypted with AES-256 and saved to _key/ folder
#   - Public key is saved to _key/ folder
#   - Private key never touches disk in plaintext
#
# REQUIREMENTS
#   - macOS with Keychain Access
#   - OpenSSL
#
# OUTPUT
#   - _key/GitExec_RSA.pub (public key)
#   - _key/GitExec_RSA.key (encrypted private key backup)
#   - Private key stored in Login Keychain
#     Service: "GitExec_RSA"
#     Account: Current user
#
# NOTES
#   Project: GitExec
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
$(echo -e "${CYAN}GitExec RSA Key Generator v1.0.1${NC}")

$(echo -e "${YELLOW}SYNOPSIS${NC}")
  Generate RSA key pair for GitExec script signing

$(echo -e "${YELLOW}USAGE${NC}")
  ./GitExec-gen_rsa_keys.sh [OPTIONS]

$(echo -e "${YELLOW}OPTIONS${NC}")
  -h, --help        Show this help message
  -f, --force       Overwrite existing keys without prompting
  --import FILE     Import encrypted private key from backup file
  --key SERVICE     Set key service name (default: GitExec_RSA)
  --size BITS       Set key size in bits (default: 4096)

$(echo -e "${YELLOW}EXAMPLES${NC}")
  # Normal operation (interactive)
  ./GitExec-gen_rsa_keys.sh

  # Force overwrite existing keys
  ./GitExec-gen_rsa_keys.sh --force

  # Import encrypted key from backup
  ./GitExec-gen_rsa_keys.sh --import _key/GitExec_RSA.key

  # Import with force (no prompts)
  ./GitExec-gen_rsa_keys.sh --import _key/GitExec_RSA.key --force

  # Custom key service
  ./GitExec-gen_rsa_keys.sh --key MyCustomKey

  # Larger key size
  ./GitExec-gen_rsa_keys.sh --size 8192

$(echo -e "${YELLOW}OUTPUT${NC}")
  _key/GitExec_RSA.pub       Public key (plaintext, safe to commit)
  _key/GitExec_RSA.key       Encrypted private key backup (AES-256)
  Keychain                   Private key (for signing)
  _logs/gen_rsa_keys/        Generation log

$(echo -e "${YELLOW}SECURITY${NC}")
  - Private key stored in macOS Keychain
  - Encrypted backup for disaster recovery
  - Never store plaintext private key in Git

$(echo -e "${YELLOW}NOTES${NC}")
  - Keys are stored in Keychain with service: GitExec_RSA
  - Encrypted backup requires passphrase (store in password manager)
  - Minimum recommended key size: 4096 bits

EOF
    exit 0
}

# Parse command line arguments
FORCE_MODE=false
IMPORT_MODE=false
IMPORT_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help|-\?)
            show_help
            ;;
        -f|--force)
            FORCE_MODE=true
            shift
            ;;
        --import)
            IMPORT_MODE=true
            IMPORT_FILE="$2"
            shift 2
            ;;
        --key)
            KEY_SERVICE="$2"
            shift 2
            ;;
        --size)
            KEY_SIZE="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Error: Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Get script location - this script should be in _gen/_setup/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_DIR="$(cd "$SCRIPT_DIR/../../_key" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Configuration
KEY_SIZE="${KEY_SIZE:-4096}"
KEY_SERVICE="${KEY_SERVICE:-GitExec_RSA}"
KEY_ACCOUNT="$USER"
PUBLIC_KEY_FILE="$KEY_DIR/${KEY_SERVICE}.pub"
ENCRYPTED_PRIVATE_KEY_FILE="$KEY_DIR/${KEY_SERVICE}.key"

# Prepare log file
LOG_DIR="$REPO_ROOT/_logs/gen_rsa_keys"
if [[ ! -d "$LOG_DIR" ]]; then
    mkdir -p "$LOG_DIR"
fi

TIMESTAMP=$(date '+%Y-%m-%d_%H%M%S')
LOG_FILE="$LOG_DIR/${TIMESTAMP}.log"

# Start logging
exec > >(tee -a "$LOG_FILE")
exec 2>&1

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Validate key size
if [[ $KEY_SIZE -lt 2048 ]]; then
    echo -e "${RED}Error: Key size must be at least 2048 bits${NC}"
    echo "Recommended: 4096 bits or higher"
    exit 1
fi

if [[ $KEY_SIZE -lt 4096 ]]; then
    echo -e "${YELLOW}Warning: Key size less than 4096 bits is not recommended${NC}"
    echo "Current: $KEY_SIZE bits"
    echo "Recommended: 4096 bits or higher"
    echo ""
    read -p "Continue anyway? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

echo ""
echo "=========================================="
echo "  RSA Key Pair Generator"
echo "  For Script Signing"
echo "=========================================="
echo ""
echo "Date:       $(date '+%Y-%m-%d %H:%M:%S')"
echo "User:       $USER"
echo "Repository: $REPO_ROOT"
echo "Log file:   _logs/gen_rsa_keys/${TIMESTAMP}.log"
echo ""

# Check if OpenSSL is available
if ! command -v openssl &> /dev/null; then
    echo -e "${RED}Error: OpenSSL is not installed${NC}"
    exit 1
fi

################################################################################
# IMPORT MODE - Import encrypted key from backup
################################################################################
if [[ "$IMPORT_MODE" == true ]]; then
    echo ""
    echo "=========================================="
    echo "  Importing RSA Key from Backup"
    echo "=========================================="
    echo ""

    # Validate import file exists
    if [[ -z "$IMPORT_FILE" ]]; then
        echo -e "${RED}Error: No import file specified${NC}"
        echo "Use: --import <path-to-encrypted-key-file>"
        exit 1
    fi

    if [[ ! -f "$IMPORT_FILE" ]]; then
        echo -e "${RED}Error: Import file not found: $IMPORT_FILE${NC}"
        exit 1
    fi

    echo "Import file: $IMPORT_FILE"
    echo ""

    # Create temporary directory for key operations
    TEMP_DIR=$(mktemp -d)
    trap "rm -rf $TEMP_DIR" EXIT

    PRIVATE_KEY="$TEMP_DIR/private.pem"
    PUBLIC_KEY="$TEMP_DIR/public.pem"

    # Decrypt the private key
    echo "Decrypting private key..."
    echo -e "${CYAN}Enter the passphrase for the encrypted backup:${NC}"
    echo ""

    if ! openssl rsa -in "$IMPORT_FILE" -out "$PRIVATE_KEY" 2>/dev/null; then
        echo -e "${RED}Error: Failed to decrypt private key${NC}"
        echo "Please check:"
        echo "  - Passphrase is correct"
        echo "  - File is a valid encrypted RSA key"
        exit 1
    fi

    echo -e "${GREEN}✓ Successfully decrypted private key${NC}"

    # Extract public key
    if ! openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY" 2>/dev/null; then
        echo -e "${RED}Error: Failed to extract public key${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓ Extracted public key${NC}"
    echo ""

    # Check if key already exists in keychain
    if security find-generic-password -s "$KEY_SERVICE" -a "$KEY_ACCOUNT" &> /dev/null; then
        if [[ "$FORCE_MODE" == false ]]; then
            echo -e "${YELLOW}Warning: A key already exists in the keychain${NC}"
            echo "  Service: $KEY_SERVICE"
            echo "  Account: $KEY_ACCOUNT"
            echo ""
            read -p "Do you want to replace it? (yes/no): " -r
            if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
                echo "Aborted."
                exit 0
            fi
        fi
        # Delete existing key
        security delete-generic-password -s "$KEY_SERVICE" -a "$KEY_ACCOUNT" &> /dev/null
        echo -e "${GREEN}✓ Removed existing key from keychain${NC}"
    fi

    # Read private key content (includes PEM headers)
    PRIVATE_KEY_CONTENT=$(cat "$PRIVATE_KEY")

    # Convert to hex for storage (to preserve exact format including newlines)
    PRIVATE_KEY_HEX=$(echo -n "$PRIVATE_KEY_CONTENT" | xxd -p | tr -d '\n')

    # Store private key in keychain as generic password (hex-encoded)
    security add-generic-password \
        -a "$KEY_ACCOUNT" \
        -s "$KEY_SERVICE" \
        -w "$PRIVATE_KEY_HEX" \
        -U

    if [[ $? -ne 0 ]]; then
        echo -e "${RED}Error: Failed to store private key in keychain${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓ Stored private key in Login Keychain${NC}"

    # Check if public key file already exists
    if [[ -f "$PUBLIC_KEY_FILE" ]]; then
        if [[ "$FORCE_MODE" == false ]]; then
            echo -e "${YELLOW}Warning: $PUBLIC_KEY_FILE already exists${NC}"
            read -p "Do you want to overwrite it? (yes/no): " -r
            if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
                echo "Keeping existing public key file."
            else
                cp "$PUBLIC_KEY" "$PUBLIC_KEY_FILE"
                chmod 600 "$PUBLIC_KEY_FILE"
                echo -e "${GREEN}✓ Replaced public key: _key/${KEY_SERVICE}.pub${NC}"
            fi
        else
            cp "$PUBLIC_KEY" "$PUBLIC_KEY_FILE"
            chmod 600 "$PUBLIC_KEY_FILE"
            echo -e "${GREEN}✓ Replaced public key: _key/${KEY_SERVICE}.pub${NC}"
        fi
    else
        # Create _key directory if it doesn't exist
        if [[ ! -d "$KEY_DIR" ]]; then
            mkdir -p "$KEY_DIR"
            echo -e "${GREEN}✓ Created directory: _key/${NC}"
        fi

        cp "$PUBLIC_KEY" "$PUBLIC_KEY_FILE"
        chmod 600 "$PUBLIC_KEY_FILE"
        echo -e "${GREEN}✓ Saved public key to: _key/${KEY_SERVICE}.pub${NC}"
    fi

    # Verify we can retrieve the key from keychain
    if ! security find-generic-password -s "$KEY_SERVICE" -a "$KEY_ACCOUNT" -w &> /dev/null; then
        echo -e "${RED}Error: Cannot verify keychain access${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓ Verified private key is accessible in keychain${NC}"

    # Test signing with the retrieved key
    echo ""
    echo "Testing key retrieval and signing..."

    # Retrieve key from keychain
    RETRIEVED_HEX=$(security find-generic-password -s "$KEY_SERVICE" -a "$KEY_ACCOUNT" -w 2>/dev/null)
    echo "$RETRIEVED_HEX" | xxd -r -p > "$TEMP_DIR/test_key.pem"

    # Create a test file
    echo "test" > "$TEMP_DIR/test.txt"

    # Try to sign it
    if openssl dgst -sha256 -sign "$TEMP_DIR/test_key.pem" -out "$TEMP_DIR/test.sig" "$TEMP_DIR/test.txt" 2>/dev/null; then
        echo -e "${GREEN}✓ Successfully tested signing with retrieved key${NC}"
    else
        echo -e "${RED}Error: Failed to sign test file with retrieved key${NC}"
        exit 1
    fi

    # Verify the signature
    if openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$TEMP_DIR/test.sig" "$TEMP_DIR/test.txt" 2>/dev/null; then
        echo -e "${GREEN}✓ Successfully verified test signature${NC}"
    else
        echo -e "${RED}Error: Failed to verify test signature${NC}"
        exit 1
    fi

    echo ""
    echo "=========================================="
    echo -e "${GREEN}✓ RSA Key Import Complete!${NC}"
    echo "=========================================="
    echo ""
    echo -e "${CYAN}Keychain Details:${NC}"
    echo "  Service: $KEY_SERVICE"
    echo "  Account: $KEY_ACCOUNT"
    echo "  Storage: Login Keychain (generic password)"
    echo ""
    echo -e "${CYAN}Files:${NC}"
    echo "  Public key: _key/${KEY_SERVICE}.pub"
    echo "  Encrypted backup: $IMPORT_FILE"
    echo ""
    echo -e "${CYAN}Next Steps:${NC}"
    echo "  1. Run GitExec-gen_sigs.sh to sign your scripts"
    echo "  2. Verify signatures are working correctly"
    echo ""
    echo "=========================================="

    exit 0
fi

################################################################################
# GENERATION MODE - Generate new RSA key pair
################################################################################

# Check if key already exists in keychain
if security find-generic-password -s "$KEY_SERVICE" -a "$KEY_ACCOUNT" &> /dev/null; then
    echo -e "${YELLOW}Warning: A key already exists in the keychain${NC}"
    echo "  Service: $KEY_SERVICE"
    echo "  Account: $KEY_ACCOUNT"
    echo ""
    read -p "Do you want to replace it? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        echo "Aborted."
        exit 0
    fi
    # Delete existing key
    security delete-generic-password -s "$KEY_SERVICE" -a "$KEY_ACCOUNT" &> /dev/null
    echo -e "${GREEN}✓ Removed existing key${NC}"
    echo ""
fi

# Check if public key file already exists
if [[ -f "$PUBLIC_KEY_FILE" ]]; then
    echo -e "${YELLOW}Warning: $PUBLIC_KEY_FILE already exists${NC}"
    read -p "Do you want to overwrite it? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        echo "Aborted."
        exit 0
    fi
    rm "$PUBLIC_KEY_FILE"
    echo -e "${GREEN}✓ Removed existing public key${NC}"
    echo ""
fi

# Check if encrypted private key backup already exists
if [[ -f "$ENCRYPTED_PRIVATE_KEY_FILE" ]]; then
    echo -e "${YELLOW}Warning: $ENCRYPTED_PRIVATE_KEY_FILE already exists${NC}"
    read -p "Do you want to overwrite it? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        echo "Aborted."
        exit 0
    fi
    rm "$ENCRYPTED_PRIVATE_KEY_FILE"
    echo -e "${GREEN}✓ Removed existing encrypted private key backup${NC}"
    echo ""
fi

# Create _key directory if it doesn't exist
if [[ ! -d "$KEY_DIR" ]]; then
    mkdir -p "$KEY_DIR"
    echo -e "${GREEN}✓ Created directory: _key/${NC}"
fi

echo "Generating RSA key pair..."
echo "  Key size: $KEY_SIZE bits"
echo ""

# Create temporary directory for key generation
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

PRIVATE_KEY="$TEMP_DIR/private.pem"
PUBLIC_KEY="$TEMP_DIR/public.pem"

# Generate private key
openssl genrsa -out "$PRIVATE_KEY" $KEY_SIZE 2>/dev/null

if [[ $? -ne 0 ]]; then
    echo -e "${RED}Error: Failed to generate RSA private key${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Generated RSA private key${NC}"

# Extract public key
openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY" 2>/dev/null

if [[ $? -ne 0 ]]; then
    echo -e "${RED}Error: Failed to extract public key${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Extracted public key${NC}"

# Read private key content (includes PEM headers)
PRIVATE_KEY_CONTENT=$(cat "$PRIVATE_KEY")

# Convert to hex for storage (to preserve exact format including newlines)
PRIVATE_KEY_HEX=$(echo -n "$PRIVATE_KEY_CONTENT" | xxd -p | tr -d '\n')

# Store private key in keychain as generic password (hex-encoded)
security add-generic-password \
    -a "$KEY_ACCOUNT" \
    -s "$KEY_SERVICE" \
    -w "$PRIVATE_KEY_HEX" \
    -U

if [[ $? -ne 0 ]]; then
    echo -e "${RED}Error: Failed to store private key in keychain${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Stored private key in Login Keychain${NC}"

# Create encrypted backup of private key for secure storage (1Password, etc.)
echo ""
echo "Creating encrypted backup of private key..."
echo -e "${CYAN}You will be prompted to create a passphrase for the encrypted backup.${NC}"
echo -e "${CYAN}Store this passphrase securely (e.g., in 1Password).${NC}"
echo ""

# Encrypt private key with AES-256-CBC
openssl rsa -in "$PRIVATE_KEY" -aes256 -out "$ENCRYPTED_PRIVATE_KEY_FILE" 2>/dev/null

if [[ $? -ne 0 ]]; then
    echo -e "${RED}Error: Failed to create encrypted backup${NC}"
    exit 1
fi

chmod 600 "$ENCRYPTED_PRIVATE_KEY_FILE"
echo -e "${GREEN}✓ Created encrypted backup: _key/${KEY_SERVICE}.key${NC}"

# Copy public key to repository
cp "$PUBLIC_KEY" "$PUBLIC_KEY_FILE"
chmod 600 "$PUBLIC_KEY_FILE"

echo -e "${GREEN}✓ Saved public key to: _key/${KEY_SERVICE}.pub${NC}"

# Verify we can retrieve the key from keychain
if security find-generic-password -s "$KEY_SERVICE" -a "$KEY_ACCOUNT" -w &> /dev/null; then
    echo -e "${GREEN}✓ Verified private key is accessible in keychain${NC}"
else
    echo -e "${RED}Error: Cannot verify keychain access${NC}"
    exit 1
fi

# Test signing with the retrieved key
echo ""
echo "Testing key retrieval and signing..."

# Retrieve key from keychain
RETRIEVED_HEX=$(security find-generic-password -s "$KEY_SERVICE" -a "$KEY_ACCOUNT" -w 2>/dev/null)
echo "$RETRIEVED_HEX" | xxd -r -p > "$TEMP_DIR/test_key.pem"

# Create a test file
echo "test" > "$TEMP_DIR/test.txt"

# Try to sign it
if openssl dgst -sha256 -sign "$TEMP_DIR/test_key.pem" -out "$TEMP_DIR/test.sig" "$TEMP_DIR/test.txt" 2>/dev/null; then
    echo -e "${GREEN}✓ Successfully tested signing with retrieved key${NC}"
else
    echo -e "${RED}Error: Failed to sign test file with retrieved key${NC}"
    exit 1
fi

# Verify the signature
if openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$TEMP_DIR/test.sig" "$TEMP_DIR/test.txt" 2>/dev/null; then
    echo -e "${GREEN}✓ Successfully verified test signature${NC}"
else
    echo -e "${RED}Error: Failed to verify test signature${NC}"
    exit 1
fi

echo ""
echo "=========================================="
echo -e "${GREEN}✓ RSA Key Pair Generation Complete!${NC}"
echo "=========================================="
echo ""
echo -e "${CYAN}Keychain Details:${NC}"
echo "  Service: $KEY_SERVICE"
echo "  Account: $KEY_ACCOUNT"
echo "  Storage: Login Keychain (generic password)"
echo ""
echo -e "${CYAN}Files Created:${NC}"
echo "  Public key: _key/${KEY_SERVICE}.pub"
echo "  Encrypted private key backup: _key/${KEY_SERVICE}.key (passphrase protected)"
echo ""
echo -e "${CYAN}Security:${NC}"
echo "  Private key: Stored securely in macOS Keychain"
echo "  Private key backup: Encrypted in _key/${KEY_SERVICE}.key (AES-256)"
echo "  Private key: Never saved to disk in plaintext"
echo "  Key size: $KEY_SIZE bits"
echo ""
echo -e "${CYAN}Next Steps:${NC}"
echo "  1. Store the passphrase for ${KEY_SERVICE}.key in 1Password/password manager"
echo "  2. Commit _key/${KEY_SERVICE}.pub to git (public key - safe to commit)"
echo "  3. Commit _key/${KEY_SERVICE}.key to git (encrypted backup - safe to commit)"
echo "  4. Run generate-signatures.sh to sign your scripts"
echo ""
echo -e "${YELLOW}Important:${NC}"
echo "  - Keep your keychain password secure"
echo "  - Keep the ${KEY_SERVICE}.key passphrase secure"
echo "  - Back up your keychain"
echo "  - DO NOT commit private key in plaintext (never create ${KEY_SERVICE}.pem)"
echo ""
echo -e "${YELLOW}Important:${NC}"
echo "  - Keep your keychain password secure"
echo "  - Keep the ${KEY_SERVICE}.key passphrase secure"
echo "  - Back up your keychain"
echo "  - DO NOT commit private key in plaintext (never create ${KEY_SERVICE}.pem)"
echo "=========================================="

exit 0