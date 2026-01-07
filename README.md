# GitExec Framework

Secure script management and execution framework for Remote Monitoring and Management (RMM) platforms.

## Overview

GitExec is a security-focused framework that enables RMM platforms to securely download and execute scripts from private GitHub repositories on managed endpoints. The framework provides encrypted credential storage, RSA signature verification, and cross-platform support for Windows and macOS systems.

## Key Features

- **Secure Credential Storage** - GitHub Personal Access Tokens (PAT) and RSA public keys encrypted using platform-native security (DPAPI on Windows, Keychain on macOS)
- **Signature Verification** - RSA public key infrastructure ready for script integrity verification
- **Simple Deployment** - Deploy the framework once, execute any script on-demand
- **Version Control Integration** - All scripts tracked in Git with full history
- **Cross-Platform Support** - Unified framework for both Windows and macOS endpoints
- **Flexible Execution** - Run scripts as SYSTEM/root or as logged-in users
- **Dual-Secret Security** - Both GitHub PAT and RSA public key required and managed together
- **Modular Architecture** - Bootstrap scripts download core libraries at runtime

## Repository Structure

```
GitExec/
├── _framework/              # GitExec execution framework
│   ├── _bootstrap/         # Bootstrap scripts (download core modules)
│   │   ├── WIN-GitExec.ps1
│   │   └── macOS-GitExec.sh
│   ├── _library/           # Core libraries (downloaded by bootstrap)
│   │   ├── WIN-GitExec-core.psm1
│   │   └── macOS-GitExec-core.sh
│   ├── _setup/             # Initial secrets configuration
│   │   ├── WIN-GitExec_Secrets.ps1
│   │   └── macOS-GitExec_Secrets.sh
│   └── README.md           # Detailed framework documentation
│
├── _bin/                    # Repository maintenance tools
│   ├── GitExec-gen_sigs.sh
│   ├── WIN-GitExec-gen_sigs.ps1
│   └── _setup/
│       ├── GitExec-gen_rsa_keys.sh
│       └── WIN-GitExec-gen_rsa_keys.ps1
│
├── _key/                    # RSA public key for verification
│   └── AC-RMM_RSA_public.key
│
├── _sig/                    # Script signatures (mirrors repo structure)
│   └── _framework/
│
└── RMM-Scripts/            # Your payload scripts go here
    ├── macOS/
    └── Windows/
```

## Quick Start

### 1. Generate GitHub Personal Access Token

Create a fine-grained personal access token with read-only access to this repository:

1. Navigate to [GitHub Settings → Fine-grained tokens](https://github.com/settings/tokens?type=beta)
2. Click **Generate new token**
3. Configure the token:
   - **Name:** `GitExec-ReadOnly`
   - **Expiration:** 90 days (recommended, rotate regularly)
   - **Repository access:** Only select repositories → Choose this repository
   - **Permissions:** Repository permissions → Contents → **Read-only**
4. Click **Generate token**
5. Copy the token (format: `github_pat_...`)

### 2. Retrieve RSA Public Key

Locate the RSA public key in this repository at `_key/AC-RMM_RSA_public.key`. Copy the entire contents including the header and footer markers:

```
-----BEGIN PUBLIC KEY-----
MIICIjANBg...
-----END PUBLIC KEY-----
```

### 3. Deploy Secrets to Endpoints

Choose the appropriate script for your platform and deploy via your RMM system.

**Windows (PowerShell):**

```powershell
# One-time setup per endpoint (both secrets required)
$GitExec_GitHubPAT = "github_pat_YOUR_TOKEN_HERE"
$GitExec_RSA_Pub = "-----BEGIN PUBLIC KEY-----
MIICIjANBg...
-----END PUBLIC KEY-----"
.\_framework\_setup\WIN-GitExec_Secrets.ps1
```

**macOS (Bash):**

```bash
# One-time setup per endpoint (both secrets required)
GitExec_GitHubPAT="github_pat_YOUR_TOKEN_HERE" \
GitExec_RSA_Pub="-----BEGIN PUBLIC KEY-----
MIICIjANBg...
-----END PUBLIC KEY-----" \
./_framework/_setup/macOS-GitExec_Secrets.sh
```

### 4. Execute Scripts

Once configured, execute any script from this repository. All variables are RMM-provided (no editing of bootstrap scripts required).

**Windows:**

```powershell
# Set in your RMM platform
$github_Org = "YOUR_GITHUB_ORG"
$github_Repo = "YOUR_SCRIPTS_REPO"
$scriptUrl = "https://github.com/YOUR_GITHUB_ORG/YOUR_SCRIPTS_REPO/blob/main/scripts/Windows/example-script.ps1"
.\_framework\_bootstrap\WIN-GitExec.ps1
```

**macOS:**

```bash
# Set in your RMM platform
github_Org="YOUR_GITHUB_ORG" \
github_Repo="YOUR_SCRIPTS_REPO" \
scriptUrl="https://github.com/YOUR_GITHUB_ORG/YOUR_SCRIPTS_REPO/blob/main/scripts/macOS/example-script.sh" \
./_framework/_bootstrap/macOS-GitExec.sh
```

### 5. Add Custom Scripts

1. Create your script in `RMM-Scripts/Windows/` or `RMM-Scripts/macOS/`
2. Commit and push to GitHub
3. Execute via the framework using the GitHub URL

## How It Works

```
┌──────────────────────────────────────────────────────────────┐
│                    Execution Flow                            │
└──────────────────────────────────────────────────────────────┘

1. RMM deploys framework script to endpoint
2. Framework retrieves encrypted credentials from local storage
3. Framework downloads target script from GitHub using PAT
4. Framework verifies script signature (optional, infrastructure ready)
5. Script executes on endpoint (as SYSTEM/root or logged-in user)
6. Results return to RMM console
7. Downloaded script automatically deleted from endpoint
```

## Security Model

### Credential Storage

**Windows:**
- **Storage:** DPAPI encryption with LocalMachine scope
- **Location:** `C:\ProgramData\GitExec\`
- **Files:**
  - `GitExecPAT.bin` - Encrypted GitHub PAT
  - `GitExecRSA.bin` - Encrypted RSA public key
- **Access Control:** Administrators and SYSTEM only

**macOS:**
- **Storage:** System Keychain (`/Library/Keychains/System.keychain`)
- **PAT Entry:**
  - Service: `com.gitexec.github-pat`
  - Account: `gitexec_pat`
- **RSA Entry:**
  - Service: `com.gitexec.rsa-public-key`
  - Account: `gitexec_rsa_pub`
- **Access Control:** Root and admin users only

### Dual-Secret Requirement

Both secrets are required and managed as a unit:

- **GitHub PAT** - Authenticates to download scripts from private repository
- **RSA Public Key** - Verifies script signatures before execution (infrastructure ready)

Both secrets must be configured during initial setup and are cleared together when removing credentials.

### GitHub PAT Permissions

The GitHub PAT requires minimal permissions:

- ✅ Repository Contents: **Read-only**
- ❌ No write access
- ❌ No admin access
- ❌ No access to other repositories

### Signature Verification

RSA signature verification infrastructure is ready for deployment:

- All scripts can be signed with a private key (stored securely by maintainer)
- Public key distributed to endpoints via secrets configuration
- Framework can verify signatures before execution using stored public key

## Deployment

Bootstrap scripts download the core library from GitHub at runtime.

**Features:**
- Small footprint on endpoints (~10KB bootstrap)
- Always uses latest framework code
- Automatic updates without redeployment
- Signature verification of downloaded library

**Files:**
- Windows: `_framework/_bootstrap/WIN-GitExec.ps1`
- macOS: `_framework/_bootstrap/macOS-GitExec.sh`

## Advanced Usage

### Run Scripts as Logged-In Users

**Windows:**

```powershell
$github_Org = "YOUR_GITHUB_ORG"
$github_Repo = "YOUR_SCRIPTS_REPO"
$scriptUrl = "https://github.com/YOUR_GITHUB_ORG/YOUR_SCRIPTS_REPO/blob/main/scripts/Windows/user-config.ps1"
$runAsUser = $true
.\_framework\_bootstrap\WIN-GitExec.ps1
```

**macOS:**

```bash
github_Org="YOUR_GITHUB_ORG" \
github_Repo="YOUR_SCRIPTS_REPO" \
scriptUrl="https://github.com/YOUR_GITHUB_ORG/YOUR_SCRIPTS_REPO/blob/main/scripts/macOS/user-setup.sh" \
runAsUser="true" \
./_framework/_bootstrap/macOS-GitExec.sh
```

### Bypass GitHub CDN Cache

For immediate updates without waiting for CDN cache expiration:

**Windows:**

```powershell
$github_Org = "YOUR_GITHUB_ORG"
$github_Repo = "YOUR_SCRIPTS_REPO"
$scriptUrl = "https://github.com/YOUR_GITHUB_ORG/YOUR_SCRIPTS_REPO/blob/main/scripts/Windows/hotfix.ps1"
$useAPI = $true
.\_framework\_bootstrap\WIN-GitExec.ps1
```

**macOS:**

```bash
github_Org="YOUR_GITHUB_ORG" \
github_Repo="YOUR_SCRIPTS_REPO" \
scriptUrl="https://github.com/YOUR_GITHUB_ORG/YOUR_SCRIPTS_REPO/blob/main/scripts/macOS/hotfix.sh" \
useAPI="true" \
./_framework/_bootstrap/macOS-GitExec.sh
```

### Update Secrets

When rotating your GitHub PAT or updating your RSA key:

**Windows:**

```powershell
$GitExec_GitHubPAT = "github_pat_NEW_TOKEN_HERE"
$GitExec_RSA_Pub = "-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----"
$force_update = $true
.\_framework\_setup\WIN-GitExec_Secrets.ps1
```

**macOS:**

```bash
GitExec_GitHubPAT="github_pat_NEW_TOKEN_HERE" \
GitExec_RSA_Pub="-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----" \
force_update="true" \
./_framework/_setup/macOS-GitExec_Secrets.sh
```

### Remove Secrets

To remove stored credentials from an endpoint:

**Windows:**

```powershell
$clear_variable = $true
.\_framework\_setup\WIN-GitExec_Secrets.ps1
```

**macOS:**

```bash
clear_variable="true" ./_framework/_setup/macOS-GitExec_Secrets.sh
```

## Exit Codes

The framework returns standardized exit codes for automation:

- `0` - Success
- `1` - Critical error or authentication failure
- `>1` - Script-specific error code

When running as multiple users (Windows `$runAsUser = $true` or macOS `runAsUser="true"`):

- Returns `1` if any user script fails critically
- Returns highest exit code if no critical failures
- Returns `0` if all user scripts succeed

## Maintenance

### Generate RSA Keys

Run once to create RSA key pair for signing (maintainer only):

**macOS/Linux:**

```bash
cd _bin/_setup
./GitExec-gen_rsa_keys.sh
```

**Windows:**

```powershell
cd _bin\_setup
.\WIN-GitExec-gen_rsa_keys.ps1
```

This creates:
- Private key stored in Keychain/secure location
- Public key saved to `_key/AC-RMM_RSA_public.key`

### Generate Signatures

After adding or modifying scripts, generate new signatures:

**macOS/Linux:**

```bash
cd _bin
./GitExec-gen_sigs.sh
```

**Windows:**

```powershell
cd _bin
.\WIN-GitExec-gen_sigs.ps1
```

This creates/updates `.sig` files in the `_sig/` folder mirroring repository structure.

## Troubleshooting

### Common Issues

**"No stored PAT found" or "No stored secrets found"**

- Ensure the secrets setter script was run first
- Verify both GitHub PAT and RSA public key were provided
- Confirm script ran with correct privileges (SYSTEM/root)

**"Failed to download script"**

- Check that GitHub PAT has not expired
- Verify network connectivity to github.com
- Confirm script URL is correct and accessible

**"Must run as SYSTEM/root"**

- Framework scripts require elevated privileges
- Configure RMM to run with SYSTEM (Windows) or root (macOS) privileges

**Script URL format errors**

- Use standard GitHub URLs, not raw URLs
- Example: `https://github.com/org/repo/blob/main/path/script.ps1`
- Framework automatically converts to appropriate format

### Getting Help

1. Review script headers for detailed parameter documentation
2. Check `_framework/README.md` for comprehensive framework documentation
3. Verify GitHub PAT permissions and expiration
4. Examine RMM logs for execution output and error messages

## Contributing

### Adding New Scripts

1. Create your script in the appropriate folder:
   - Windows scripts: `RMM-Scripts/Windows/`
   - macOS scripts: `RMM-Scripts/macOS/`
2. Test locally to ensure proper functionality
3. Commit with descriptive message following conventions
4. Generate signatures: `cd _bin && ./GitExec-gen_sigs.sh` (or Windows equivalent)
5. Push to GitHub

### Script Naming Conventions

**Windows Scripts:**
- Format: `WIN-[Action]-[Target].ps1`
- Example: `WIN-Get-SystemInfo.ps1`
- Capitalize each word in PowerShell naming style

**macOS Scripts:**
- Format: `macOS-[action]-[target].sh`
- Example: `macOS-get-systeminfo.sh`
- Use lowercase with hyphens for bash naming style

### Best Practices

- ✅ Include comprehensive script headers with synopsis, description, and examples
- ✅ Use consistent parameter naming across similar scripts
- ✅ Return appropriate exit codes (0 = success, 1 = critical error, >1 = specific errors)
- ✅ Clean up temporary files before exiting
- ✅ Log important operations for troubleshooting
- ✅ Test on clean endpoints before production deployment
- ✅ Document any external dependencies or requirements

## Version Information

**Current Version:** 1.0.0

**Release Date:** 2025-10-21

**Project Name:** GitExec

### Version History

**v1.0.0 (2025-10-21)**

- Initial stable release of GitExec framework
- Dual-secret security model (GitHub PAT + RSA public key)
- Cross-platform support (Windows and macOS)
- Modular bootstrap architecture
- Signature verification infrastructure
- Secure credential storage using DPAPI and Keychain
- Multi-user execution support
- Comprehensive logging and error handling

### Previous Project Name

Formerly known as RMMSecureGitRunner. Renamed to GitExec for clarity and brevity.

## License

Copyright (C) 2026 Peet, Inc.

This project is licensed under the GNU General Public License v2.0 (GPLv2).

See the [LICENSE](LICENSE) file or [https://www.gnu.org/licenses/old-licenses/gpl-2.0.html](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html) for details.

## Security Notice

**Important Security Practices:**

- Rotate GitHub PATs every 90 days minimum
- Never commit PATs or private keys to version control
- Use fine-grained PATs with read-only permissions only
- Regularly audit PAT access in GitHub settings
- Monitor RMM logs for unusual activity
- Keep framework scripts updated to latest version
- Store private RSA keys securely (never in repository)
- Test secret rotation procedures before PAT expiration

## Additional Resources

- **Framework Documentation:** See `_framework/README.md` for detailed technical documentation
- **Inspired By:** [TheFramework](https://github.com/ByteSizedITGuy/TheFramework)
- **License:** GNU General Public License v2.0
- **Repository:** [https://github.com/YOUR_GITHUB_ORG/GitExec](https://github.com/YOUR_GITHUB_ORG/GitExec)

---

**Ready to get started?** Follow the Quick Start guide above or refer to `_framework/README.md` for comprehensive technical documentation.
