<#
.SYNOPSIS
  Store GitHub PAT and RSA Public Key securely on the endpoint using DPAPI (LocalMachine).

.DESCRIPTION
  - Encrypts both secrets with DPAPI LocalMachine:
    * GitExecPAT.bin - GitHub Personal Access Token
    * GitExecRSA.bin - RSA Public Key (normalized base64)
  - Locks the secrets directory to Administrators and SYSTEM only (no inheritance).
  - Supports boolean flags: force_update ($true/$false) and clear_variable ($true/$false).
  - Does NOT seed a per-user secret. GitExec will handle per-user seeding when $runasuser = yes.
  - Both secrets are required and managed together as a unit.

.PARAMETER GitExec_GitHubPAT
  Your GitHub Personal Access Token (PAT). This should be a fine-grained PAT with read-only access to your private repository.

  How to create a GitHub PAT:
  1. Go to GitHub Settings Developer settings Personal access tokens Fine-grained tokens
  2. Click Generate new token
  3. Set token name (e.g., MSP-Scripts-ReadOnly)
  4. Set expiration (recommend 90 days, then rotate)
  5. Select repository access Only select repositories Choose your private scripts repo
  6. Set permissions Repository permissions Contents Read only
  7. Click Generate token
  8. Copy the token (starts with github_pat_...)

  Token format examples:
  - Fine-grained: github_pat_11AAAAAA...ZZZZZZZ (82 characters after prefix)
  - Classic: ghp_AAAAAAAAAA...ZZZZZZZZ (36 characters after prefix)

.PARAMETER GitExec_RSA_Pub
  RSA Public Key in PEM format for verifying script signatures.

  This should be the PUBLIC key (not private key) in PEM format with headers:
  -----BEGIN PUBLIC KEY-----
  [base64 encoded key data]
  -----END PUBLIC KEY-----

  The key can be provided as multi-line or single-line (SyncroRMM compatible).
  The script will normalize the format before encrypting and storing.

  Both GitExec_GitHubPAT and GitExec_RSA_Pub are required together.

.PARAMETER force_update
  Set to $true to overwrite existing secrets. Default is $false which will skip if secrets already exist.

.PARAMETER clear_variable
  Set to $true to delete both stored secrets (PAT and RSA key). Default is $false.

.EXAMPLE
  # RMM variable injection (Syncro and others inject before script runs)
  $GitExec_GitHubPAT = "github_pat_11AQ...FYFq"
  $GitExec_RSA_Pub = "-----BEGIN PUBLIC KEY-----
  MIICIjANBg...
  -----END PUBLIC KEY-----"
  .\WIN-Set-GitExec_Secrets.ps1

.EXAMPLE
  # Update existing secrets
  $GitExec_GitHubPAT = "github_pat_NEW_TOKEN"
  $GitExec_RSA_Pub = "-----BEGIN PUBLIC KEY-----..."
  $force_update = $true
  .\WIN-Set-GitExec_Secrets.ps1

.EXAMPLE
  # Clear/remove both stored secrets
  $clear_variable = $true
  .\WIN-Set-GitExec_Secrets.ps1

.REQUIREMENTS
  Must be run as SYSTEM (LocalSystem).

.NOTES
  Project: GitExec
  Inspired by TheFramework project: https://github.com/ByteSizedITGuy/TheFramework
  This implementation includes substantial modifications and enhancements for GitExec
  Changes in v2.0.1:
    - BREAKING: Renamed $GitHubPAT to $GitExec_GitHubPAT for cross-platform consistency with macOS
    - BREAKING: Renamed $Update_PAT to $force_update (still boolean, matches macOS naming)
    - BREAKING: Renamed $Remove_PAT to $clear_variable (still boolean, matches macOS naming)
    - BREAKING: Now requires BOTH secrets (GitExec_GitHubPAT and GitExec_RSA_Pub) for installation
    - NEW: Added support for RSA Public Key storage (GitExec_RSA_Pub parameter)
    - NEW: RSA key validation (PEM format with BEGIN/END markers)
    - NEW: RSA key normalization (strips headers, stores as base64)
    - NEW: PAT length validation (93 chars for fine-grained, 40 for classic)
    - NEW: Both secrets cleared together when clear_variable = $true
    - Updated project name from RMMSecureGitRunner to GitExec
    - Updated paths to C:\ProgramData\GitExec
    - Updated entropy string from "Org-Secret-v1" to "GitExec-Secret-v1"
    - Separate secret files: GitExecPAT.bin and GitExecRSA.bin

  Previous changes:
    - Made SyncroModule import conditional (compatibility with all RMMs)
    - Added early PAT validation with clear error messages
    - Added verification step after encryption
    - Enhanced output with detailed information
    - Removed Unicode characters for maximum compatibility
    - Added comprehensive documentation for GitHub PAT
    - Removed param() block for RMM compatibility
    - Reorganized constants to be more visible and customizable
    - Added timestamp logging for all operations
    - Added Convert-SyncroVariables for automatic type conversion (booleans, integers, arrays)
    - Simplified array security check to avoid quote parsing issues

.DISCLAIMER
  Copyright (C) 2026 Peet, Inc.
  
  Licensed under the GNU General Public License v2.0 (GPLv2).
  See <https://www.gnu.org/licenses/old-licenses/gpl-2.0.html> for details.
  
  USE AT YOUR OWN RISK:
  These scripts are provided as-is.
  You are solely responsible for validating script integrity, functionality, 
  and safety. By using these scripts, you accept full responsibility for any 
  outcomes, intended or not. No warranty is expressed or implied.
#>

# ====== RMM DETECTION & VARIABLE TRANSLATION ======
# Gorelo RMM uses text substitution: $gorelo':'varName → 'value'
if ($PSCommandPath -like 'C:\Program Files\Gorelo\Agent\AppData\Scripts\*') {
    $GITEXEC_RMM = 'gorelo'
    $GitExec_GitHubPAT = $gorelo:GitExec_GitHubPAT
    $GitExec_RSA_Pub = $gorelo:GitExec_RSA_Pub
    $force_update = $gorelo:force_update
    $clear_variable = $gorelo:clear_variable
}

# ====== SAFE ARRAY PARSER (No Invoke-Expression) ======
function ConvertTo-SafeArray {
    param([string]$ArrayString)

    # Strip @( prefix and ) suffix
    $inner = $ArrayString.Substring(2, $ArrayString.Length - 3)

    $results = @()
    $current = ""
    $inDoubleQuote = $false
    $inSingleQuote = $false

    for ($i = 0; $i -lt $inner.Length; $i++) {
        $char = $inner[$i]

        if ($char -eq '"' -and -not $inSingleQuote) {
            $inDoubleQuote = -not $inDoubleQuote
        }
        elseif ($char -eq "'" -and -not $inDoubleQuote) {
            $inSingleQuote = -not $inSingleQuote
        }
        elseif ($char -eq ',' -and -not $inDoubleQuote -and -not $inSingleQuote) {
            # End of element
            $element = $current.Trim()
            # Remove surrounding quotes if present
            if (($element.StartsWith('"') -and $element.EndsWith('"')) -or
                ($element.StartsWith("'") -and $element.EndsWith("'"))) {
                $element = $element.Substring(1, $element.Length - 2)
            }
            $results += $element
            $current = ""
        }
        else {
            $current += $char
        }
    }

    # Don't forget the last element
    if ($current.Length -gt 0) {
        $element = $current.Trim()
        if (($element.StartsWith('"') -and $element.EndsWith('"')) -or
            ($element.StartsWith("'") -and $element.EndsWith("'"))) {
            $element = $element.Substring(1, $element.Length - 2)
        }
        $results += $element
    }

    return $results
}

# ====== STRING TO TYPE CONVERSION FUNCTION ======
function Convert-SyncroVariables {
    [CmdletBinding()]
    param()

    $conversionCount = 0
    $variables = Get-Variable

    foreach ($var in $variables) {
        if ($var.Options -match "ReadOnly|Constant") {
            continue
        }

        if ($var.Value -is [string]) {
            $trimmedValue = $var.Value.Trim()
            $converted = $null

            if ($trimmedValue -imatch "^(\$)?(true|yes)$") {
                $converted = $true
            }
            elseif ($trimmedValue -imatch "^(\$)?(false|no)$") {
                $converted = $false
            }
            elseif ([int]::TryParse($trimmedValue, [ref]$null)) {
                $converted = [int]$trimmedValue
            }
            elseif ($trimmedValue -match '^@\(.+\)$') {
                # Safe array parsing without Invoke-Expression
                try {
                    $converted = ConvertTo-SafeArray $trimmedValue
                    if ($converted.Count -eq 0) {
                        $converted = $null
                    }
                } catch {
                    Write-Host "[Convert-SyncroVariables] ERROR: Array conversion failed"
                    $converted = $null
                }
            }

            if ($null -ne $converted) {
                try {
                    Set-Variable -Name $var.Name -Value $converted -Scope 1
                    $conversionCount++
                } catch {
                    Write-Host "[Convert-SyncroVariables] ERROR: Failed to set variable"
                }
            }
        }
    }
}

# ====== OPTIONAL RMM MODULE IMPORT ======
if ($env:SyncroModule) {
    try {
        Import-Module $env:SyncroModule -ErrorAction Stop
        Write-Host "SyncroModule loaded successfully"
    } catch {
        Write-Warning "SyncroModule not available - continuing without it"
    }
    
    Convert-SyncroVariables
}

# ====== CUSTOMIZABLE SETTINGS ======
if (-not $GitExec_GitHubPAT) {
    $GitExec_GitHubPAT = "ONLY_PASTE_YOUR_TOKEN_HERE_TO_HARDCODE"
}

if (-not $GitExec_RSA_Pub) {
    $GitExec_RSA_Pub = @"
-----BEGIN PUBLIC KEY-----
PASTE_YOUR_RSA_PUBLIC_KEY_HERE
-----END PUBLIC KEY-----
"@
}

if (-not $force_update) {
    $force_update = $false
}

if (-not $clear_variable) {
    $clear_variable = $false
}

$SECRET_NAME_PAT = "GitExecPAT"
$SECRET_NAME_RSA = "GitExecRSA"
$BASE_DIR = "C:\ProgramData\GitExec"
$BLOB_PATH_PAT = Join-Path $BASE_DIR "$SECRET_NAME_PAT.bin"
$BLOB_PATH_RSA = Join-Path $BASE_DIR "$SECRET_NAME_RSA.bin"
$MACHINE_GUID = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
$ENTROPY_PAT = [Text.Encoding]::UTF8.GetBytes("GitExec-ENTRO:$MACHINE_GUID`:PAT")
$ENTROPY_RSA = [Text.Encoding]::UTF8.GetBytes("GitExec-ENTRO:$MACHINE_GUID`:RSA")
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ====== LOGGING HELPER ======
function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][ValidateSet("INFO","OK","WARN","ERROR","START","COMPLETE")]
        [string]$Level
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message"
}

# ====== SECRET VALIDATION ======
if (-not $clear_variable) {
    # Validate GitHub PAT
    if (-not $GitExec_GitHubPAT) {
        Write-Log -Level ERROR -Message "GitHub PAT not provided"
        Write-Host "Both GitExec_GitHubPAT and GitExec_RSA_Pub are required"
        exit 1
    }

    if ([string]::IsNullOrWhiteSpace($GitExec_GitHubPAT)) {
        Write-Log -Level ERROR -Message "GitHub PAT is empty or whitespace"
        exit 1
    }

    if ($GitExec_GitHubPAT -eq "ONLY_PASTE_YOUR_TOKEN_HERE_TO_HARDCODE") {
        Write-Log -Level ERROR -Message "Placeholder PAT detected - replace with actual token"
        exit 1
    }

    if ($GitExec_GitHubPAT -notmatch "^(github_pat_|ghp_)") {
        Write-Log -Level ERROR -Message "PAT format invalid - must start with github_pat_ or ghp_"
        exit 1
    }

    # Validate PAT length (fine-grained: 82 chars after prefix, classic: 36 chars)
    if ($GitExec_GitHubPAT -match "^github_pat_") {
        if ($GitExec_GitHubPAT.Length -ne 93) {  # "github_pat_" (11) + 82 = 93
            Write-Log -Level ERROR -Message "Fine-grained PAT must be 93 characters total (github_pat_ + 82 chars)"
            exit 1
        }
    } elseif ($GitExec_GitHubPAT -match "^ghp_") {
        if ($GitExec_GitHubPAT.Length -ne 40) {  # "ghp_" (4) + 36 = 40
            Write-Log -Level ERROR -Message "Classic PAT must be 40 characters total (ghp_ + 36 chars)"
            exit 1
        }
    }

    # Validate RSA Public Key
    if (-not $GitExec_RSA_Pub) {
        Write-Log -Level ERROR -Message "RSA Public Key not provided"
        Write-Host "Both GitExec_GitHubPAT and GitExec_RSA_Pub are required"
        exit 1
    }

    if ([string]::IsNullOrWhiteSpace($GitExec_RSA_Pub)) {
        Write-Log -Level ERROR -Message "RSA Public Key is empty or whitespace"
        exit 1
    }

    if ($GitExec_RSA_Pub -match "PASTE_YOUR_RSA_PUBLIC_KEY_HERE") {
        Write-Log -Level ERROR -Message "Placeholder RSA key detected - replace with actual public key"
        exit 1
    }

    if ($GitExec_RSA_Pub -notmatch "-----BEGIN PUBLIC KEY-----" -or
        $GitExec_RSA_Pub -notmatch "-----END PUBLIC KEY-----") {
        Write-Log -Level ERROR -Message "RSA key must be in PEM format with BEGIN/END markers"
        exit 1
    }
}

# ====== HELPER FUNCTIONS ======
function Validate-RSAPublicKey {
    param([Parameter(Mandatory)][string]$Key)

    Write-Log -Level INFO -Message "Validating RSA public key format..."

    # Check for PEM markers (already done in validation, but double-check)
    if ($Key -notmatch "-----BEGIN PUBLIC KEY-----" -or
        $Key -notmatch "-----END PUBLIC KEY-----") {
        throw "RSA public key must be in PEM format with BEGIN/END markers"
    }

    # Extract base64 content - strip markers and ALL whitespace
    $base64Content = $Key -replace "-----BEGIN PUBLIC KEY-----","" `
                          -replace "-----END PUBLIC KEY-----","" `
                          -replace "[\s\r\n\t]",""

    if ([string]::IsNullOrWhiteSpace($base64Content)) {
        throw "No base64 content found in RSA public key"
    }

    # Validate it's decodable base64
    try {
        $null = [System.Convert]::FromBase64String($base64Content)
        Write-Log -Level OK -Message "RSA public key validated (base64 decode successful)"
    } catch {
        throw "Invalid base64 content in RSA public key: $($_.Exception.Message)"
    }

    # Return normalized base64 (no PEM headers, no whitespace)
    return $base64Content
}

function Test-IsSystem {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    return $currentIdentity.IsSystem
}

function Ensure-DpapiTypes {
    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
    if (-not ('System.Security.Cryptography.ProtectedData' -as [type])) {
        throw "DPAPI not available on this system"
    }
}

function Ensure-SecureFolder {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) {
        Write-Log -Level INFO -Message "Creating directory: $Path"
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    Write-Log -Level INFO -Message "Setting permissions (Administrators + SYSTEM only)"

    # Get current ACL and clear inherited permissions
    $acl = Get-Acl -Path $Path
    $acl.SetAccessRuleProtection($true, $false)

    # Remove all existing access rules
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } | Out-Null

    # Add rules for SYSTEM and Administrators with full control + inheritance
    foreach ($principal in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $principal,
            'FullControl',
            'ContainerInherit,ObjectInherit',
            'None',
            'Allow'
        )
        $acl.AddAccessRule($rule)
    }

    Set-Acl -Path $Path -AclObject $acl

    try {
        (Get-Item $Path).Attributes = 'Hidden,System'
        Write-Log -Level INFO -Message "Folder attributes set: Hidden, System"
    } catch {
        Write-Log -Level WARN -Message "Could not set folder attributes"
    }
}

function Save-MachineSecret {
    param([Parameter(Mandatory)][string]$Token)

    $isUpdate = Test-Path $BLOB_PATH_PAT

    Ensure-SecureFolder -Path $BASE_DIR
    Ensure-DpapiTypes

    if ($isUpdate -and -not $force_update) {
        Write-Log -Level INFO -Message "PAT already exists at: $BLOB_PATH_PAT"
        $existingFile = Get-Item $BLOB_PATH_PAT
        Write-Log -Level INFO -Message "Last modified: $($existingFile.LastWriteTime)"
        Write-Log -Level INFO -Message "To overwrite, set: force_update = `$true"
        return
    }

    if ([string]::IsNullOrWhiteSpace($Token)) {
        throw "GitHub PAT is empty or whitespace"
    }

    if ($isUpdate) {
        Write-Log -Level WARN -Message "Updating existing PAT"
    }

    Write-Log -Level INFO -Message "Encrypting GitHub PAT with DPAPI..."
    $bytes = [Text.Encoding]::UTF8.GetBytes($Token)
    $enc = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $ENTROPY_PAT, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    [System.IO.File]::WriteAllBytes($BLOB_PATH_PAT, $enc)
    Write-Log -Level OK -Message "Saved encrypted PAT to: $BLOB_PATH_PAT"
    
    Write-Log -Level INFO -Message "Verifying encryption..."
    try {
        $testEnc = [System.IO.File]::ReadAllBytes($BLOB_PATH_PAT)
        $testDec = [System.Security.Cryptography.ProtectedData]::Unprotect($testEnc, $ENTROPY_PAT, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        $testToken = [System.Text.Encoding]::UTF8.GetString($testDec)

        if ($testToken -eq $Token) {
            Write-Log -Level OK -Message "Verification successful"
        } else {
            Write-Log -Level WARN -Message "Verification failed"
            throw "PAT verification failed"
        }

        $testToken=$null
        $testDec=$null
        $testEnc=$null

    } catch {
        Write-Log -Level ERROR -Message "Failed to verify encrypted PAT"
        if (Test-Path $BLOB_PATH_PAT) {
            Remove-Item $BLOB_PATH_PAT -Force -ErrorAction SilentlyContinue
        }
        throw "PAT encryption verification failed"
    }

    $Token=$null
    $bytes=$null
    $enc=$null

    $fileInfo = Get-Item $BLOB_PATH_PAT
    Write-Log -Level OK -Message "PAT setup complete - Size: $($fileInfo.Length) bytes"
}

function Save-RSAPublicKey {
    param([Parameter(Mandatory)][string]$Key)

    $isUpdate = Test-Path $BLOB_PATH_RSA

    Ensure-SecureFolder -Path $BASE_DIR
    Ensure-DpapiTypes

    if ($isUpdate -and -not $force_update) {
        Write-Log -Level INFO -Message "RSA key already exists at: $BLOB_PATH_RSA"
        $existingFile = Get-Item $BLOB_PATH_RSA
        Write-Log -Level INFO -Message "Last modified: $($existingFile.LastWriteTime)"
        Write-Log -Level INFO -Message "To overwrite, set: force_update = `$true"
        return
    }

    # Validate and normalize (strips PEM headers, whitespace)
    $normalizedKey = Validate-RSAPublicKey -Key $Key

    if ($isUpdate) {
        Write-Log -Level WARN -Message "Updating existing RSA public key"
    }

    Write-Log -Level INFO -Message "Encrypting RSA public key with DPAPI..."
    $bytes = [Text.Encoding]::UTF8.GetBytes($normalizedKey)
    $enc = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $ENTROPY_RSA, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    [System.IO.File]::WriteAllBytes($BLOB_PATH_RSA, $enc)
    Write-Log -Level OK -Message "Saved encrypted RSA key to: $BLOB_PATH_RSA"

    Write-Log -Level INFO -Message "Verifying encryption..."
    try {
        $testEnc = [System.IO.File]::ReadAllBytes($BLOB_PATH_RSA)
        $testDec = [System.Security.Cryptography.ProtectedData]::Unprotect($testEnc, $ENTROPY_RSA, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        $testKey = [System.Text.Encoding]::UTF8.GetString($testDec)

        if ($testKey -eq $normalizedKey) {
            Write-Log -Level OK -Message "RSA key verification successful"
        } else {
            Write-Log -Level WARN -Message "RSA key verification failed"
            throw "RSA key verification failed"
        }

        $testKey=$null
        $testDec=$null
        $testEnc=$null

    } catch {
        Write-Log -Level ERROR -Message "Failed to verify encrypted RSA key"
        if (Test-Path $BLOB_PATH_RSA) {
            Remove-Item $BLOB_PATH_RSA -Force -ErrorAction SilentlyContinue
        }
        # Also clean up PAT if RSA fails (atomic operation)
        if (Test-Path $BLOB_PATH_PAT) {
            Remove-Item $BLOB_PATH_PAT -Force -ErrorAction SilentlyContinue
            Write-Log -Level WARN -Message "Cleaned up PAT due to RSA key failure"
        }
        throw "RSA key encryption verification failed"
    }

    $normalizedKey=$null
    $bytes=$null
    $enc=$null

    $fileInfo = Get-Item $BLOB_PATH_RSA
    Write-Log -Level OK -Message "RSA key setup complete - Size: $($fileInfo.Length) bytes (normalized base64)"
}

# ====== MAIN EXECUTION ======
Write-Log -Level START -Message "WIN-Set-GitExec_Secrets v2.0.1"

if (-not (Test-IsSystem)) {
    Write-Log -Level ERROR -Message "Must run as SYSTEM"
    exit 1
}
Write-Log -Level OK -Message "Running as SYSTEM"

if ($clear_variable) {
    Write-Log -Level INFO -Message "Operation: Remove both secrets"

    $removedAny = $false

    # Remove PAT
    if (Test-Path $BLOB_PATH_PAT) {
        Remove-Item -Path $BLOB_PATH_PAT -Force
        Write-Log -Level OK -Message "Removed PAT from: $BLOB_PATH_PAT"
        $removedAny = $true
    } else {
        Write-Log -Level INFO -Message "No PAT found to remove"
    }

    # Remove RSA key
    if (Test-Path $BLOB_PATH_RSA) {
        Remove-Item -Path $BLOB_PATH_RSA -Force
        Write-Log -Level OK -Message "Removed RSA key from: $BLOB_PATH_RSA"
        $removedAny = $true
    } else {
        Write-Log -Level INFO -Message "No RSA key found to remove"
    }

    if (-not $removedAny) {
        Write-Log -Level INFO -Message "No secrets found to remove"
    } else {
        Write-Log -Level OK -Message "Secrets removal complete"
    }

    exit 0
}

Write-Log -Level INFO -Message "Operation: Save both secrets"
Save-MachineSecret -Token $GitExec_GitHubPAT
Save-RSAPublicKey -Key $GitExec_RSA_Pub
Write-Log -Level COMPLETE -Message "WIN-Set-GitExec_Secrets finished"
exit 0