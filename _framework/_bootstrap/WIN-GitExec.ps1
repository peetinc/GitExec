<#
.SYNOPSIS
  WIN-GitExec.ps1 (Bootstrap)
  Bootstrap script for GitExec framework

.DESCRIPTION
  Downloads, verifies, and imports the GitExec core module
  ALL business logic is in the module - this just bootstraps it

.NOTES
  Copyright (C) 2026 Peet, Inc.
  Licensed under GPLv2
#>

$ErrorActionPreference = 'Stop'

# ====== RMM VARIABLES ======
# Set ALL of these in your RMM platform before the script runs.
#
# REQUIRED:
#   $github_Org         Your GitHub organization or username
#   $github_Repo        Repository name containing GitExec framework
#   $scriptUrl          Full GitHub URL to the script to execute
#                       Formats: github.com/.../blob/... or raw.githubusercontent.com/...
#
#   OR instead of $scriptUrl, set both:
#   $scriptUrlBase      Base URL path (e.g., https://github.com/org/repo/blob/main/scripts/Windows)
#   $scriptName         Script filename (e.g., my-script.ps1)
#
# OPTIONAL:
#   $github_Branch      Branch or tag (default: main)
#   $runAsUser          $true = run as each logged-in user, $false = run as SYSTEM (default: $false)
#   $useAPI             $true = use GitHub API (bypasses CDN cache) (default: $false)
#   $runAsUserTimeout   Seconds to wait for user scripts (default: 600)
#   $loggingMode        "None", "FrameworkOnly", or "Full" (default: "Full")
#   $logRetentionDays   Days to retain log files (default: 30)

# ====== RUNTIME (don't edit below) ======
$PROJECT_VERSION = "1.0.0"

# Validate required variables
if (-not $github_Org) { throw "github_Org is required but not set. Configure this in your RMM platform." }
if (-not $github_Repo) { throw "github_Repo is required but not set. Configure this in your RMM platform." }

# Apply defaults for optional variables
if (-not $github_Branch) { $github_Branch = "main" }

# Set runtime variables
$GITEXEC_ORG = $github_Org
$GITEXEC_REPO = $github_Repo
$GITEXEC_BRANCH = $github_Branch

# ====== THIN BOOTSTRAP FUNCTIONS ======
# FROZEN: Only update if cryptographically necessary

# Initialize DPAPI types for decryption
function Initialize-ThinDpapiTypes {
    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
    if (-not ('System.Security.Cryptography.ProtectedData' -as [type])) {
        throw "DPAPI types unavailable"
    }
}

# Unprotect DPAPI-encrypted blob (reusable helper)
function Unprotect-ThinBlob {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte[]]$Entropy
    )

    if (-not (Test-Path $Path)) {
        throw "DPAPI blob not found: $Path"
    }

    Initialize-ThinDpapiTypes
    $enc = [System.IO.File]::ReadAllBytes($Path)
    $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $enc,
        $Entropy,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    $result = [System.Text.Encoding]::UTF8.GetString($bytes)

    # Clear sensitive data from memory
    $bytes = $null
    $enc = $null

    return $result
}

# Get GitHub PAT from DPAPI storage
function Get-ThinGitHubPAT {
    try {
        $BlobPath = "C:\ProgramData\GitExec\GitExecPAT.bin"
        $MachineGuid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
        $Entropy = [System.Text.Encoding]::UTF8.GetBytes("GitExec-ENTRO:$MachineGuid`:PAT")

        $PAT = Unprotect-ThinBlob -Path $BlobPath -Entropy $Entropy
        return $PAT
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve GitHub PAT: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[ERROR] Run WIN-GitExec_Secrets.ps1 first to configure authentication" -ForegroundColor Red
        throw "GitHub PAT retrieval failed"
    }
}

# Parse ASN.1 length field (for legacy RSA key parsing)
function Read-ThinASN1Length {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][ref]$Offset
    )

    $firstByte = $Bytes[$Offset.Value]
    $Offset.Value++

    if ($firstByte -band 0x80) {
        $numLengthBytes = $firstByte -band 0x7F
        $length = 0
        for ($i = 0; $i -lt $numLengthBytes; $i++) {
            $length = ($length -shl 8) -bor $Bytes[$Offset.Value]
            $Offset.Value++
        }
        return $length
    } else {
        return $firstByte
    }
}

# Import RSA public key from SPKI format (Windows PowerShell 5.1 fallback)
function Import-ThinRSAPublicKeyFromSPKI {
    param([Parameter(Mandatory)][byte[]]$KeyBytes)

    $offset = 0

    # Read outer SEQUENCE
    if ($KeyBytes[$offset] -ne 0x30) { throw "Invalid SPKI: expected SEQUENCE" }
    $offset++
    $null = Read-ThinASN1Length -Bytes $KeyBytes -Offset ([ref]$offset)

    # Read algorithm SEQUENCE
    if ($KeyBytes[$offset] -ne 0x30) { throw "Invalid SPKI: expected algorithm SEQUENCE" }
    $offset++
    $algLen = Read-ThinASN1Length -Bytes $KeyBytes -Offset ([ref]$offset)
    $offset += $algLen

    # Read BIT STRING
    if ($KeyBytes[$offset] -ne 0x03) { throw "Invalid SPKI: expected BIT STRING" }
    $offset++
    $null = Read-ThinASN1Length -Bytes $KeyBytes -Offset ([ref]$offset)
    $offset++  # Skip unused bits indicator

    # Read RSA public key SEQUENCE
    if ($KeyBytes[$offset] -ne 0x30) { throw "Invalid RSA key: expected SEQUENCE" }
    $offset++
    $null = Read-ThinASN1Length -Bytes $KeyBytes -Offset ([ref]$offset)

    # Read modulus INTEGER
    if ($KeyBytes[$offset] -ne 0x02) { throw "Invalid RSA key: expected modulus INTEGER" }
    $offset++
    $modulusLen = Read-ThinASN1Length -Bytes $KeyBytes -Offset ([ref]$offset)

    # Skip leading zero if present
    if ($KeyBytes[$offset] -eq 0x00) {
        $offset++
        $modulusLen--
    }
    $modulus = $KeyBytes[$offset..($offset + $modulusLen - 1)]
    $offset += $modulusLen

    # Read exponent INTEGER
    if ($KeyBytes[$offset] -ne 0x02) { throw "Invalid RSA key: expected exponent INTEGER" }
    $offset++
    $exponentLen = Read-ThinASN1Length -Bytes $KeyBytes -Offset ([ref]$offset)
    $exponent = $KeyBytes[$offset..($offset + $exponentLen - 1)]

    # Create RSA parameters and import
    $rsaParams = New-Object System.Security.Cryptography.RSAParameters
    $rsaParams.Modulus = $modulus
    $rsaParams.Exponent = $exponent

    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsa.ImportParameters($rsaParams)

    return $rsa
}

# Verify script signature using RSA public key from DPAPI
function Test-ThinSignature {
    param($File, $Sig)

    try {
        # Get RSA public key from DPAPI
        $BlobPath = "C:\ProgramData\GitExec\GitExecRSA.bin"
        $MachineGuid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
        $Entropy = [System.Text.Encoding]::UTF8.GetBytes("GitExec-ENTRO:$MachineGuid`:RSA")

        $Base64Key = Unprotect-ThinBlob -Path $BlobPath -Entropy $Entropy

        # Create RSA and verify
        $KeyBytes = [System.Convert]::FromBase64String($Base64Key)
        $FileBytes = [System.IO.File]::ReadAllBytes($File)
        $SigBytes = [System.IO.File]::ReadAllBytes($Sig)
        $SHA256 = [System.Security.Cryptography.SHA256]::Create()
        $Hash = $SHA256.ComputeHash($FileBytes)

        $rsa = $null
        $isValid = $false

        # Try modern method first (.NET 5+ / PowerShell Core)
        $importMethod = [System.Security.Cryptography.RSA].GetMethod('ImportSubjectPublicKeyInfo')
        if ($importMethod) {
            $rsa = [System.Security.Cryptography.RSA]::Create()
            $rsa.ImportSubjectPublicKeyInfo($KeyBytes, [ref]$null)

            $isValid = $rsa.VerifyHash($Hash, $SigBytes,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        } else {
            # Fallback for Windows PowerShell 5.1 - use manual SPKI parser
            $rsa = Import-ThinRSAPublicKeyFromSPKI -KeyBytes $KeyBytes
            $hashAlgOID = [System.Security.Cryptography.CryptoConfig]::MapNameToOID("SHA256")
            $isValid = $rsa.VerifyHash($Hash, $hashAlgOID, $SigBytes)
        }

        # Cleanup
        $SHA256.Dispose()
        $rsa.Dispose()

        return $isValid
    }
    catch {
        Write-Host "[ERROR] Signature verification failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ====== DOWNLOAD AND IMPORT MODULE ======
# Get GitHub PAT for authenticated downloads
$GitHubPAT = Get-ThinGitHubPAT

# Build URLs from configuration
$BaseUrl = "https://raw.githubusercontent.com/$GITEXEC_ORG/$GITEXEC_REPO/$GITEXEC_BRANCH"
$ModuleUrl = "$BaseUrl/_framework/_library/WIN-GitExec-core.psm1"
$SigUrl = "$BaseUrl/_sig/_framework/_library/WIN-GitExec-core.psm1.sig"

$TempModule = "$env:TEMP\GitExec-Core_$PID.psm1"
$TempSig = "$TempModule.sig"

# Create headers with authentication
$Headers = @{
    Authorization = "Bearer $GitHubPAT"
    "User-Agent" = "GitExec/$PROJECT_VERSION"
}

try {
    # Download module and signature with authentication
    Invoke-WebRequest -Uri $ModuleUrl -OutFile $TempModule -Headers $Headers -ErrorAction Stop
    Invoke-WebRequest -Uri $SigUrl -OutFile $TempSig -Headers $Headers -ErrorAction Stop

    # SECURITY: Clear PAT from memory immediately after downloads complete
    $GitHubPAT = $null
    $Headers = $null
    Remove-Variable -Name GitHubPAT -ErrorAction SilentlyContinue
    Remove-Variable -Name Headers -ErrorAction SilentlyContinue

    # Verify signature
    if (-not (Test-ThinSignature $TempModule $TempSig)) {
        throw "Module signature verification failed"
    }

    # Export all user/RMM variables to global scope for module to access
    # Exclude: PowerShell automatic variables, thin script internals
    $ExcludePattern = '^(PS|ExecutionContext|Host|Home|PID|PWD|ShellId|StackTrace|MyInvocation|_|args|input|foreach|switch|this|ErrorActionPreference|ProgressPreference|WarningPreference|VerbosePreference|DebugPreference|InformationPreference|WhatIfPreference|ConfirmPreference|Error|GITEXEC_|GitHubPAT|BaseUrl|ModuleUrl|SigUrl|TempModule|TempSig|Headers|ExcludePattern)$'

    Get-Variable | Where-Object {
        $_.Name -notmatch $ExcludePattern -and
        $_.Options -notmatch 'ReadOnly|Constant'
    } | ForEach-Object {
        Set-Variable -Name $_.Name -Value $_.Value -Scope Global -Force
    }

    # Import module and run
    Import-Module $TempModule -Force
    Invoke-GitExecInit
}
catch {
    Write-Host "[ERROR] Bootstrap failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
finally {
    # Cleanup sensitive data and temp files
    Remove-Variable -Name GitHubPAT -ErrorAction SilentlyContinue
    Remove-Variable -Name Headers -ErrorAction SilentlyContinue
    Remove-Module GitExec-Core -ErrorAction SilentlyContinue
    Remove-Item $TempModule, $TempSig -ErrorAction SilentlyContinue
}
