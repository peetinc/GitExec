# GitExec Framework Documentation

Comprehensive technical documentation for the GitExec execution framework.

## Overview

The GitExec framework provides a secure infrastructure for Remote Monitoring and Management (RMM) platforms to download and execute scripts from private GitHub repositories on managed endpoints. This folder contains all framework components required for deployment and operation.

## Framework Components

### Bootstrap Scripts

Minimal bootstrap scripts that download core functionality from GitHub at runtime.

**Windows:** `_bootstrap/WIN-GitExec.ps1`
- Downloads and imports core module from GitHub
- Verifies module signature before execution
- Small footprint (approximately 10 KB)
- Always uses latest framework code
- Requires network connectivity

**macOS:** `_bootstrap/macOS-GitExec.sh`
- Downloads and sources core library from GitHub
- Verifies library signature before execution
- Small footprint (approximately 3 KB)
- Always uses latest framework code
- Requires network connectivity

### Core Libraries

**Windows:** `_library/WIN-GitExec-core.psm1`
- Core business logic for Windows framework
- Downloaded and imported by bootstrap script at runtime
- Contains all execution functions
- Signed for integrity verification

**macOS:** `_library/macOS-GitExec-core.sh`
- Core business logic for macOS framework
- Downloaded and sourced by bootstrap script at runtime
- Contains all execution functions
- Signed for integrity verification

### Setup Scripts

**Windows:** `_setup/WIN-GitExec_Secrets.ps1`
- Configures GitHub PAT and RSA public key on Windows endpoints
- Encrypts secrets using DPAPI with LocalMachine scope
- Creates secure directory structure
- Validates secret format before storage

**macOS:** `_setup/macOS-GitExec_Secrets.sh`
- Configures GitHub PAT and RSA public key on macOS endpoints
- Stores secrets in System Keychain
- Creates secure directory structure
- Validates secret format before storage

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    GitExec Architecture                         │
└─────────────────────────────────────────────────────────────────┘

┌──────────────┐
│ RMM Platform │ (SyncroRMM, NinjaRMM, etc.)
└──────┬───────┘
       │
       │ 1. Deploy framework script
       ▼
┌──────────────┐
│   Endpoint   │ (Windows or macOS)
│  Framework   │
└──────┬───────┘
       │
       │ 2. Retrieve encrypted credentials
       ▼
┌──────────────┐
│ DPAPI / Key  │ (Secure credential storage)
│   chain      │
└──────┬───────┘
       │
       │ 3. Download script using GitHub PAT
       ▼
┌──────────────┐
│    GitHub    │ (Private repository)
│  Repository  │
└──────┬───────┘
       │
       │ 4. Return script content
       ▼
┌──────────────┐
│  Signature   │ (Optional: Verify RSA signature)
│ Verification │
└──────┬───────┘
       │
       │ 5. Execute script
       ▼
┌──────────────┐
│   Script     │ (SYSTEM/root or user context)
│  Execution   │
└──────┬───────┘
       │
       │ 6. Return results to RMM
       ▼
┌──────────────┐
│ RMM Console  │ (Output and exit codes)
└──────────────┘
```

## Setup Scripts

### WIN-GitExec_Secrets.ps1

**Purpose:** One-time configuration of GitHub PAT and RSA public key on Windows endpoints.

**Version:** 1.0.0

**Requirements:**
- Must run as SYSTEM (LocalSystem account)
- PowerShell 5.1 or later
- Network access not required
- Both GitHub PAT and RSA public key must be provided

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `$GitExec_GitHubPAT` | String | Yes | GitHub Personal Access Token (fine-grained, read-only) |
| `$GitExec_RSA_Pub` | String | Yes | RSA public key in PEM format |
| `$force_update` | Boolean | No | Overwrite existing secrets (default: `$false`) |
| `$clear_variable` | Boolean | No | Delete both stored secrets (default: `$false`) |

**Storage Location:**
- Directory: `C:\ProgramData\GitExec\`
- PAT File: `GitExecPAT.bin` (DPAPI encrypted)
- RSA File: `GitExecRSA.bin` (DPAPI encrypted, base64 format)

**Encryption:**
- Method: Data Protection API (DPAPI)
- Scope: LocalMachine
- Entropy: Unique string per secret type
- Access: Administrators and SYSTEM only

**Usage Examples:**

```powershell
# Initial setup (both secrets required)
$GitExec_GitHubPAT = "github_pat_11AQ...FYFq"
$GitExec_RSA_Pub = "-----BEGIN PUBLIC KEY-----
MIICIjANBg...
-----END PUBLIC KEY-----"
.\_framework\_setup\WIN-GitExec_Secrets.ps1
```

```powershell
# Update existing secrets
$GitExec_GitHubPAT = "github_pat_NEW_TOKEN"
$GitExec_RSA_Pub = "-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----"
$force_update = $true
.\_framework\_setup\WIN-GitExec_Secrets.ps1
```

```powershell
# Remove both secrets
$clear_variable = $true
.\_framework\_setup\WIN-GitExec_Secrets.ps1
```

**Exit Codes:**
- `0` - Success
- `1` - Critical error (missing parameters, invalid format, encryption failure)

---

### macOS-GitExec_Secrets.sh

**Purpose:** One-time configuration of GitHub PAT and RSA public key on macOS endpoints.

**Version:** 1.0.0

**Requirements:**
- Must run as root (sudo)
- macOS 10.12 or later
- security command-line tool
- Both GitHub PAT and RSA public key must be provided

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `GitExec_GitHubPAT` | String | Yes | GitHub Personal Access Token (fine-grained, read-only) |
| `GitExec_RSA_Pub` | String | Yes | RSA public key in PEM format |
| `force_update` | String | No | Overwrite existing secrets: `"true"` or `"false"` (default: `"false"`) |
| `clear_variable` | String | No | Delete both stored secrets: `"true"` or `"false"` (default: `"false"`) |

**Storage Location:**
- Keychain: `/Library/Keychains/System.keychain`
- PAT Service: `com.gitexec.github-pat`
- PAT Account: `gitexec_pat`
- RSA Service: `com.gitexec.rsa-public-key`
- RSA Account: `gitexec_rsa_pub`

**Encryption:**
- Method: macOS System Keychain
- Access: Root and admin users only
- Format: PAT stored as-is, RSA key stored as normalized base64

**Usage Examples:**

```bash
# Initial setup (both secrets required)
GitExec_GitHubPAT="github_pat_11AQ...FYFq" \
GitExec_RSA_Pub="-----BEGIN PUBLIC KEY-----
MIICIjANBg...
-----END PUBLIC KEY-----" \
./_framework/_setup/macOS-GitExec_Secrets.sh
```

```bash
# Update existing secrets
GitExec_GitHubPAT="github_pat_NEW_TOKEN" \
GitExec_RSA_Pub="-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----" \
force_update="true" \
./_framework/_setup/macOS-GitExec_Secrets.sh
```

```bash
# Remove both secrets
clear_variable="true" ./_framework/_setup/macOS-GitExec_Secrets.sh
```

**Exit Codes:**
- `0` - Success
- `1` - Critical error (missing parameters, invalid format, keychain failure)

---

## Execution Scripts

### WIN-GitExec.ps1 (Bootstrap)

**Purpose:** Download and execute PowerShell scripts from GitHub repository.

**Version:** 1.0.0

**Requirements:**
- Secrets must be configured first (using WIN-GitExec_Secrets.ps1)
- Must run as SYSTEM for accessing DPAPI secrets
- Network access to github.com and raw.githubusercontent.com or api.github.com

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `$github_Org` | String | Yes | None | GitHub organization or username |
| `$github_Repo` | String | Yes | None | Repository containing GitExec framework |
| `$scriptUrl` | String | Yes | None | GitHub URL to PowerShell script |
| `$github_Branch` | String | No | `"main"` | Branch or tag to use |
| `$runAsUser` | Boolean | No | `$false` | Run as logged-in users instead of SYSTEM |
| `$useAPI` | Boolean | No | `$false` | Use GitHub API (bypasses CDN cache) |
| `$runAsUserTimeout` | Integer | No | `600` | Timeout in seconds for user tasks |
| `$loggingMode` | String | No | `"Full"` | Logging level: `"None"`, `"FrameworkOnly"`, `"Full"` |
| `$logRetentionDays` | Integer | No | `30` | Days to retain log files |

**Features:**
- Automatic URL conversion (blob URLs to raw or API format)
- Multi-user execution support
- Exit code aggregation
- Signature verification (infrastructure ready)
- Comprehensive logging with timestamps
- Automatic cleanup of temporary files

**URL Format:**

Supported formats:
- `https://github.com/owner/repo/blob/main/script.ps1`
- `https://github.com/owner/repo/blob/branch/path/to/script.ps1`
- `https://raw.githubusercontent.com/owner/repo/main/script.ps1` (also accepted)

**Usage Examples:**

```powershell
# Run as SYSTEM
$github_Org = "YOUR_GITHUB_ORG"
$github_Repo = "YOUR_SCRIPTS_REPO"
$scriptUrl = "https://github.com/YOUR_GITHUB_ORG/YOUR_SCRIPTS_REPO/blob/main/scripts/Windows/system-info.ps1"
.\_framework\_bootstrap\WIN-GitExec.ps1
```

```powershell
# Run as all logged-in users
$github_Org = "YOUR_GITHUB_ORG"
$github_Repo = "YOUR_SCRIPTS_REPO"
$scriptUrl = "https://github.com/YOUR_GITHUB_ORG/YOUR_SCRIPTS_REPO/blob/main/scripts/Windows/user-config.ps1"
$runAsUser = $true
.\_framework\_bootstrap\WIN-GitExec.ps1
```

```powershell
# Use GitHub API for cache bypass
$github_Org = "YOUR_GITHUB_ORG"
$github_Repo = "YOUR_SCRIPTS_REPO"
$scriptUrl = "https://github.com/YOUR_GITHUB_ORG/YOUR_SCRIPTS_REPO/blob/main/scripts/Windows/hotfix.ps1"
$useAPI = $true
.\_framework\_bootstrap\WIN-GitExec.ps1
```

**Exit Codes:**
- When `$runAsUser = $false`: Returns executed script's exit code
- When `$runAsUser = $true`:
  - `0` - All user scripts succeeded
  - `1` - At least one user script exited with code 1
  - `>1` - Highest exit code from user scripts

---

### macOS-GitExec.sh (Bootstrap)

**Purpose:** Download and execute shell scripts from GitHub repository.

**Version:** 1.0.0

**Requirements:**
- Secrets must be configured first (using macOS-GitExec_Secrets.sh)
- Must run as root for accessing System Keychain
- Network access to github.com and raw.githubusercontent.com or api.github.com
- OpenSSL for signature verification

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `github_Org` | String | Yes | None | GitHub organization or username |
| `github_Repo` | String | Yes | None | Repository containing GitExec framework |
| `scriptUrl` | String | Yes | None | GitHub URL to shell script |
| `github_Branch` | String | No | `"main"` | Branch or tag to use |
| `runAsUser` | String | No | `"false"` | Run as logged-in users: `"true"` or `"false"` |
| `useAPI` | String | No | `"false"` | Use GitHub API: `"true"` or `"false"` |
| `runAsUserTimeout` | Integer | No | `600` | Timeout in seconds for user tasks |
| `loggingMode` | String | No | `"Full"` | Logging level: `"None"`, `"FrameworkOnly"`, `"Full"` |
| `logRetentionDays` | Integer | No | `30` | Days to retain log files |

**Features:**
- Automatic URL conversion
- Multi-user execution with isolation
- Exit code aggregation
- Signature verification (infrastructure ready)
- Comprehensive logging with timestamps
- Automatic cleanup of temporary files
- Per-user directory isolation with 700 permissions

**URL Format:**

Supported formats:
- `https://github.com/owner/repo/blob/main/script.sh`
- `https://github.com/owner/repo/blob/branch/path/to/script.sh`
- `https://raw.githubusercontent.com/owner/repo/main/script.sh` (also accepted)

**Usage Examples:**

```bash
# Run as root
github_Org="YOUR_GITHUB_ORG" \
github_Repo="YOUR_SCRIPTS_REPO" \
scriptUrl="https://github.com/YOUR_GITHUB_ORG/YOUR_SCRIPTS_REPO/blob/main/scripts/macOS/system-info.sh" \
./_framework/_bootstrap/macOS-GitExec.sh
```

```bash
# Run as all logged-in users
github_Org="YOUR_GITHUB_ORG" \
github_Repo="YOUR_SCRIPTS_REPO" \
scriptUrl="https://github.com/YOUR_GITHUB_ORG/YOUR_SCRIPTS_REPO/blob/main/scripts/macOS/user-config.sh" \
runAsUser="true" \
./_framework/_bootstrap/macOS-GitExec.sh
```

```bash
# Use GitHub API for cache bypass
github_Org="YOUR_GITHUB_ORG" \
github_Repo="YOUR_SCRIPTS_REPO" \
scriptUrl="https://github.com/YOUR_GITHUB_ORG/YOUR_SCRIPTS_REPO/blob/main/scripts/macOS/hotfix.sh" \
useAPI="true" \
./_framework/_bootstrap/macOS-GitExec.sh
```

**Directory Structure:**

```
/Library/Application Support/GitExec/
├── Device/                     (root:admin 770 - System/root scripts)
│   └── {uuid}.sh              (Downloaded scripts, auto-deleted)
├── User/                       (root:admin 755 - User base directory)
│   ├── username1/              (username1:staff 700 - User isolation)
│   │   ├── {uuid}.sh
│   │   ├── {uuid}.sh.sig
│   │   └── wrapper_{uuid}.sh
│   └── username2/              (username2:staff 700 - User isolation)
└── Logs/                       (Logging directory)
    ├── System/                 (System execution logs)
    ├── User/                   (User execution logs)
    └── Temp/                   (Temporary logs)
```

**Exit Codes:**
- When `runAsUser="false"`: Returns executed script's exit code
- When `runAsUser="true"`:
  - `0` - All user scripts succeeded
  - `1` - At least one user script exited with code 1
  - `>1` - Highest exit code from user scripts

---

## Security Architecture

### Credential Protection

**Windows DPAPI:**
1. Secrets encrypted using Data Protection API (DPAPI)
2. LocalMachine scope ensures system-wide availability
3. Unique entropy per secret type
4. Only SYSTEM and Administrators can decrypt
5. Secrets survive reboots and user logoffs

**macOS Keychain:**
1. Secrets stored in System Keychain
2. Access restricted to root and admin users
3. Survives reboots and user logoffs
4. Integration with macOS security framework
5. Audit trail of keychain access

### Network Security

**GitHub Authentication:**
- Fine-grained Personal Access Token (PAT)
- Read-only access to repository contents
- No write or administrative permissions
- Time-limited tokens (90-day rotation recommended)
- Token revocation support

**Transport Security:**
- All downloads over HTTPS
- TLS 1.2 or later required
- Certificate validation enforced
- No fallback to insecure protocols

### Script Integrity

**Signature Verification (Infrastructure Ready):**
1. RSA public key stored securely on endpoint
2. Scripts signed with maintainer's private key
3. Framework verifies signature before execution
4. Execution refused for invalid or missing signatures
5. Protects against tampering and unauthorized modifications

### Execution Security

**Privilege Model:**
- Framework requires SYSTEM/root privileges
- Scripts can run as SYSTEM/root or logged-in users
- User execution isolated in dedicated directories
- Temporary files cleaned up after execution
- Exit code validation and aggregation

## Deployment Workflow

### Initial Setup (One-Time per Endpoint)

#### Step 1: Prepare Secrets

**Generate GitHub PAT:**
1. Navigate to [GitHub Settings → Fine-grained tokens](https://github.com/settings/tokens?type=beta)
2. Click **Generate new token**
3. Configure token:
   - Name: `GitExec-ReadOnly`
   - Expiration: 90 days
   - Repository access: Only select repositories
   - Permissions: Contents → Read-only
4. Copy token (format: `github_pat_...`)

**Retrieve RSA Public Key:**
1. Locate `_key/AC-RMM_RSA_public.key` in repository
2. Copy entire contents including BEGIN/END markers

#### Step 2: Deploy Secrets to Endpoints

**Windows:**
```powershell
$GitExec_GitHubPAT = "github_pat_YOUR_TOKEN"
$GitExec_RSA_Pub = "-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----"
.\_framework\_setup\WIN-GitExec_Secrets.ps1
```

**macOS:**
```bash
GitExec_GitHubPAT="github_pat_YOUR_TOKEN" \
GitExec_RSA_Pub="-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----" \
./_framework/_setup/macOS-GitExec_Secrets.sh
```

#### Step 3: Verify Configuration

**Windows:**
```powershell
# Secrets should exist
Test-Path "C:\ProgramData\GitExec\GitExecPAT.bin"
Test-Path "C:\ProgramData\GitExec\GitExecRSA.bin"
```

**macOS:**
```bash
# Secrets should exist
security find-generic-password -s "com.gitexec.github-pat" /Library/Keychains/System.keychain
security find-generic-password -s "com.gitexec.rsa-public-key" /Library/Keychains/System.keychain
```

### Regular Script Execution

#### Step 1: Create or Update Scripts

1. Add scripts to `RMM-Scripts/Windows/` or `RMM-Scripts/macOS/`
2. Test locally
3. Commit and push to GitHub
4. Optionally generate signatures

#### Step 2: Execute via RMM

**Windows:**
```powershell
$github_Org = "YOUR_GITHUB_ORG"
$github_Repo = "YOUR_SCRIPTS_REPO"
$scriptUrl = "https://github.com/YOUR_GITHUB_ORG/YOUR_SCRIPTS_REPO/blob/main/scripts/Windows/your-script.ps1"
.\_framework\_bootstrap\WIN-GitExec.ps1
```

**macOS:**
```bash
github_Org="YOUR_GITHUB_ORG" \
github_Repo="YOUR_SCRIPTS_REPO" \
scriptUrl="https://github.com/YOUR_GITHUB_ORG/YOUR_SCRIPTS_REPO/blob/main/scripts/macOS/your-script.sh" \
./_framework/_bootstrap/macOS-GitExec.sh
```

#### Step 3: Monitor Results

1. Check RMM console for output
2. Review exit codes for success/failure
3. Examine logs if troubleshooting needed

## Troubleshooting

### Windows Issues

**"No stored PAT found" or "No stored secrets found"**

Cause: Secrets not configured or DPAPI decryption failed.

Solution:
1. Run `WIN-GitExec_Secrets.ps1` to configure secrets
2. Ensure both `$GitExec_GitHubPAT` and `$GitExec_RSA_Pub` are provided
3. Verify script runs as SYSTEM
4. Check that files exist:
   - `C:\ProgramData\GitExec\GitExecPAT.bin`
   - `C:\ProgramData\GitExec\GitExecRSA.bin`

**"Failed to download script" or "HTTP error"**

Cause: Network connectivity, expired PAT, or invalid URL.

Solution:
1. Verify network connectivity to github.com
2. Check that GitHub PAT has not expired
3. Confirm PAT has read access to repository
4. Validate script URL format
5. Try with `$useAPI = $true` to bypass CDN cache

**"Must run as SYSTEM"**

Cause: Script running as Administrator or user account.

Solution:
1. Configure RMM to execute as SYSTEM (LocalSystem)
2. Do not run interactively
3. Use RMM platform's SYSTEM execution mode

### macOS Issues

**"GitExec secrets not found" or "Failed to retrieve secrets from keychain"**

Cause: Secrets not configured or keychain access denied.

Solution:
1. Run `macOS-GitExec_Secrets.sh` to configure secrets
2. Ensure both `GitExec_GitHubPAT` and `GitExec_RSA_Pub` are provided
3. Verify script runs as root
4. Check keychain entries:
   ```bash
   security find-generic-password -s "com.gitexec.github-pat" /Library/Keychains/System.keychain
   security find-generic-password -s "com.gitexec.rsa-public-key" /Library/Keychains/System.keychain
   ```

**"This script must be run as root"**

Cause: Script running as standard user.

Solution:
1. Use `sudo` when running script manually
2. Configure RMM to execute with root privileges
3. Verify RMM platform supports root execution

**"Failed to download script" or "curl error"**

Cause: Network connectivity, expired PAT, or invalid URL.

Solution:
1. Verify network connectivity to github.com
2. Check that GitHub PAT has not expired
3. Confirm PAT has read access to repository
4. Validate script URL format
5. Try with `useAPI="true"` to bypass CDN cache

### Cross-Platform Issues

**GitHub PAT Expired**

Symptoms: "Failed to download", "401 Unauthorized", "403 Forbidden"

Solution:
1. Generate new GitHub PAT
2. Update secrets using `force_update` flag:
   - Windows: `$force_update = $true`
   - macOS: `force_update="true"`
3. Deploy updated secrets to all endpoints

**Invalid Script URL**

Symptoms: "404 Not Found", "Failed to parse URL"

Solution:
1. Use standard GitHub URLs: `https://github.com/owner/repo/blob/branch/path/script.ext`
2. Do not use raw URLs unless testing
3. Ensure branch name is correct (e.g., `main` not `master`)
4. Verify script path matches repository structure

**Signature Verification Failures**

Symptoms: "Invalid signature", "Signature verification failed"

Solution:
1. Regenerate signatures: Run `macOS-GitExec-gen_sigs.sh` or `WIN-GitExec-gen_sigs.ps1`
2. Verify RSA public key is correct
3. Confirm script has not been modified outside of repository
4. Check that signature file exists in `_sig/` directory

## GitHub PAT Configuration

### Creating Fine-Grained PAT

1. Navigate to [GitHub Settings → Fine-grained tokens](https://github.com/settings/tokens?type=beta)
2. Click **Generate new token**
3. Configure token:
   - **Token name:** `GitExec-ReadOnly`
   - **Expiration:** 90 days (recommended)
   - **Repository access:** Only select repositories → Choose this repository
   - **Repository permissions:**
     - Contents: **Read-only**
     - (No other permissions needed)
4. Click **Generate token**
5. Copy token immediately (will not be shown again)

### Token Format

**Fine-grained tokens:**
- Format: `github_pat_` + 82 characters
- Example: `github_pat_11AAAAAA...ZZZZZZZ`
- Recommended for GitExec

**Classic tokens (also supported):**
- Format: `ghp_` + 36 characters
- Example: `ghp_AAAAAAA...ZZZZZZZ`
- Less secure than fine-grained tokens

### Secret Rotation

Rotate secrets every 90 days minimum:

**Windows:**
```powershell
$GitExec_GitHubPAT = "github_pat_NEW_TOKEN"
$GitExec_RSA_Pub = "-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----"
$force_update = $true
.\_framework\_setup\WIN-GitExec_Secrets.ps1
```

**macOS:**
```bash
GitExec_GitHubPAT="github_pat_NEW_TOKEN" \
GitExec_RSA_Pub="-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----" \
force_update="true" \
./_framework/_setup/macOS-GitExec_Secrets.sh
```

## Advanced Configuration

### Logging Options

Control logging verbosity and retention:

| Mode | Description | Use Case |
|------|-------------|----------|
| `None` | No logging | Production environments with external logging |
| `FrameworkOnly` | Framework operations only | Troubleshooting framework issues |
| `Full` | Framework + script output | Development and debugging |

**Example:**
```powershell
$github_Org = "YOUR_GITHUB_ORG"
$github_Repo = "YOUR_SCRIPTS_REPO"
$scriptUrl = "https://github.com/YOUR_GITHUB_ORG/YOUR_SCRIPTS_REPO/blob/main/script.ps1"
$loggingMode = "FrameworkOnly"
$logRetentionDays = 7
.\_framework\_bootstrap\WIN-GitExec.ps1
```

### Custom Timeout for User Execution

Adjust timeout for long-running user scripts:

**Windows:**
```powershell
$github_Org = "YOUR_GITHUB_ORG"
$github_Repo = "YOUR_SCRIPTS_REPO"
$scriptUrl = "https://github.com/YOUR_GITHUB_ORG/YOUR_SCRIPTS_REPO/blob/main/long-task.ps1"
$runAsUser = $true
$runAsUserTimeout = 1800  # 30 minutes
.\_framework\_bootstrap\WIN-GitExec.ps1
```

**macOS:**
```bash
github_Org="YOUR_GITHUB_ORG" \
github_Repo="YOUR_SCRIPTS_REPO" \
scriptUrl="https://github.com/YOUR_GITHUB_ORG/YOUR_SCRIPTS_REPO/blob/main/long-task.sh" \
runAsUser="true" \
runAsUserTimeout=1800 \
./_framework/_bootstrap/macOS-GitExec.sh
```

### RMM Variables (Bootstrap Scripts)

All variables are RMM-provided (no editing of bootstrap scripts required):

**Windows:**
```powershell
# Required
$github_Org = "yourorg"
$github_Repo = "your-scripts-repo"
$scriptUrl = "https://github.com/yourorg/your-scripts-repo/blob/main/scripts/Windows/script.ps1"

# Optional
$github_Branch = "main"  # or "stable", "v1.0.0"
$runAsUser = $false
$useAPI = $true
.\_framework\_bootstrap\WIN-GitExec.ps1
```

**macOS:**
```bash
# Required
github_Org="yourorg" \
github_Repo="your-scripts-repo" \
scriptUrl="https://github.com/yourorg/your-scripts-repo/blob/main/scripts/macOS/script.sh" \
# Optional
github_Branch="main" \
runAsUser="false" \
useAPI="true" \
./_framework/_bootstrap/macOS-GitExec.sh
```

## Related Documentation

- **Main README:** `../README.md` - Project overview and quick start
- **Signature Generation:** `../_bin/macOS-GitExec-gen_sigs.sh` - Generate script signatures
- **Key Generation:** `../_bin/_setup/macOS-GitExec-gen_rsa_keys.sh` - Generate RSA key pair
- **Public Key:** `../_key/AC-RMM_RSA_public.key` - RSA public key for distribution

## Version Information

**Framework Version:** 1.0.0

**Last Updated:** 2025-10-21

**License:** GNU General Public License v2.0 (GPLv2)

**Copyright:** (C) 2026 Peet, Inc.

## Support

For issues, questions, or contributions:

1. Check this documentation thoroughly
2. Review script headers for parameter details
3. Examine log files for error messages
4. Verify GitHub PAT permissions and expiration
5. Ensure correct execution privileges (SYSTEM/root)

---

**Important:** These framework scripts are infrastructure components that must be deployed to endpoints. They download and execute your payload scripts from the `RMM-Scripts/` directory. Always test framework updates on non-production endpoints first.
