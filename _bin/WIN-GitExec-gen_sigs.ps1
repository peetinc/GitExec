################################################################################
# WIN-GitExec-gen_sigs.ps1
#
# SYNOPSIS
#   Recursively generates RSA signatures for all GitExec scripts in the repository
#
# DESCRIPTION
#   This script scans all files in the directory where it's located (and
#   subdirectories) and creates RSA .sig files using the private key stored
#   in Windows Credential Manager (DPAPI).
#
# REQUIREMENTS
#   - PowerShell 5.1+ or PowerShell Core 7+
#   - RSA private key stored in Credential Manager (use WIN-GitExec-gen_rsa_keys.ps1)
#
# OUTPUT
#   - .sig files for each script file
#   - Signatures saved in _sig\ folder (mirrors repository structure)
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

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(HelpMessage="Show help message")]
    [Alias('h', '?')]
    [switch]$Help,

    [Parameter(HelpMessage="Automatically sign files without prompting")]
    [Alias('y')]
    [switch]$Yes,

    [Parameter(HelpMessage="Force re-signing of all files (even valid signatures)")]
    [Alias('f')]
    [switch]$Force,

    [Parameter(HelpMessage="Check signature status without signing")]
    [Alias('c')]
    [switch]$Check,

    [Parameter(HelpMessage="Minimal output (status + files only)")]
    [Alias('q')]
    [switch]$Quiet,

    [Parameter(HelpMessage="Silent mode (no output except errors)")]
    [Alias('s')]
    [switch]$Silent,

    [Parameter(HelpMessage="Use alternate key service (default: GitExec_RSA)")]
    [string]$KeyService = "GitExec_RSA",

    [Parameter(HelpMessage="Scripts directory to sign (default: scripts)")]
    [string]$ScriptsDir = "scripts"
)

# Set strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

################################################################################
# Helper Functions
################################################################################

function Show-Help {
    $helpText = @"

GitExec Signature Generator v1.0.0 (Windows)

SYNOPSIS
  Generate RSA signatures for all scripts in the repository

USAGE
  .\WIN-GitExec-gen_sigs.ps1 [OPTIONS]

OPTIONS
  -Help, -h, -?         Show this help message
  -Yes, -y              Automatically sign files without prompting
  -Force, -f            Force re-signing of all files (even valid signatures)
  -Check, -c            Check signature status without signing
  -Quiet, -q            Minimal output (status + files only)
  -Silent, -s           Silent mode (no output except errors)
  -KeyService <NAME>    Use alternate key service (default: GitExec_RSA)
  -ScriptsDir <DIR>     Scripts directory to sign (default: scripts)

EXAMPLES
  # Normal operation (interactive)
  .\WIN-GitExec-gen_sigs.ps1

  # Automation - sign what needs signing without prompting
  .\WIN-GitExec-gen_sigs.ps1 -Yes

  # Force re-sign everything without prompting
  .\WIN-GitExec-gen_sigs.ps1 -Force

  # Check status only, don't sign
  .\WIN-GitExec-gen_sigs.ps1 -Check

  # Quiet mode (status + files only)
  .\WIN-GitExec-gen_sigs.ps1 -Quiet

  # Silent automation
  .\WIN-GitExec-gen_sigs.ps1 -Yes -Silent

  # Use custom key service
  .\WIN-GitExec-gen_sigs.ps1 -KeyService MyCustomKey

FLAGS COMPARISON
  (none)    Full verbose output
  -Quiet    Status tags + filenames + summary
  -Silent   No output except errors
  -Check    Report status only, don't sign anything
  -Yes      Auto-approve signing without prompting
  -Force    Re-sign ALL files (including valid) without prompting

FILES
  Input:  RMM-Scripts\, _framework\ (scripts to sign)
  Output: _sig\ (signatures), _logs\gen_sigs\ (logs)
  Key:    _key\GitExec_RSA.pub (public key)

NOTES
  - Verifies existing signatures before signing
  - Only signs files that are new, outdated, or invalid
  - Creates timestamped log in _logs\gen_sigs\
  - Signs library files in _framework\_library\

"@
    Write-Host $helpText
    exit 0
}

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    if (-not $script:Silent) {
        Write-Host $Message -ForegroundColor $Color
    }
}

function Write-Success {
    param([string]$Message)
    if (-not $script:Silent) {
        Write-ColorOutput "✔ $Message" -Color Green
    }
}

function Write-Warning {
    param([string]$Message)
    if (-not $script:Silent) {
        Write-ColorOutput "Warning: $Message" -Color Yellow
    }
}

function Write-Error {
    param([string]$Message)
    Write-ColorOutput "Error: $Message" -Color Red
}

function Write-Info {
    param([string]$Message)
    if (-not $script:Silent) {
        Write-ColorOutput $Message -Color Cyan
    }
}

function Write-Verbose-Custom {
    param([string]$Message)
    if (-not $script:Quiet -and -not $script:Silent) {
        Write-Host $Message
    }
}

function Confirm-Action {
    param(
        [string]$Message
    )

    if ($script:Yes -or $script:Force) {
        return $true
    }

    $response = Read-Host "$Message (yes/no)"
    return $response -match '^[Yy](es)?$'
}

################################################################################
# Credential Manager Functions (using Windows DPAPI)
################################################################################

function Get-CredentialManagerKey {
    param(
        [string]$Target
    )

    try {
        $credPath = "$env:LOCALAPPDATA\GitExec\Credentials"
        $credFile = Join-Path $credPath "${Target}.dat"

        if (-not (Test-Path $credFile)) {
            return $null
        }

        # Decrypt using DPAPI (CurrentUser scope)
        $encryptedData = Get-Content $credFile -Raw
        $secureString = $encryptedData | ConvertTo-SecureString

        # Convert secure string back to plain text
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
        try {
            $privateKeyPem = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
            return $privateKeyPem
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        }
    }
    catch {
        Write-Error "Failed to retrieve private key: $_"
        return $null
    }
}

function Test-CredentialManagerKey {
    param(
        [string]$Target
    )

    $credPath = "$env:LOCALAPPDATA\GitExec\Credentials"
    $credFile = Join-Path $credPath "${Target}.dat"

    return Test-Path $credFile
}

################################################################################
# RSA Signature Functions
################################################################################

function Import-RsaPrivateKey {
    param(
        [string]$PrivateKeyPem
    )

    try {
        # Extract base64 data from PEM
        $PrivateKeyPem -match '-----BEGIN.*?-----(.+)-----END.*?-----' | Out-Null
        $privateKeyBase64 = $matches[1] -replace '\s', ''
        $privateKeyBytes = [Convert]::FromBase64String($privateKeyBase64)

        # Create RSA provider and import key
        $rsa = [System.Security.Cryptography.RSA]::Create()
        $rsa.ImportRSAPrivateKey($privateKeyBytes, [ref]$null)

        return $rsa
    }
    catch {
        Write-Error "Failed to import RSA private key: $_"
        return $null
    }
}

function Import-RsaPublicKey {
    param(
        [string]$PublicKeyPem
    )

    try {
        # Extract base64 data from PEM
        $PublicKeyPem -match '-----BEGIN.*?-----(.+)-----END.*?-----' | Out-Null
        $publicKeyBase64 = $matches[1] -replace '\s', ''
        $publicKeyBytes = [Convert]::FromBase64String($publicKeyBase64)

        # Create RSA provider and import key
        $rsa = [System.Security.Cryptography.RSA]::Create()

        # Try SubjectPublicKeyInfo format first (standard)
        try {
            $rsa.ImportSubjectPublicKeyInfo($publicKeyBytes, [ref]$null)
        }
        catch {
            # Fallback to RSAPublicKey format
            $rsa.ImportRSAPublicKey($publicKeyBytes, [ref]$null)
        }

        return $rsa
    }
    catch {
        Write-Error "Failed to import RSA public key: $_"
        return $null
    }
}

function New-RsaSignature {
    param(
        [System.Security.Cryptography.RSA]$Rsa,
        [string]$FilePath
    )

    try {
        # Read file data
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)

        # Sign data with SHA256 and PKCS1 padding (OpenSSL compatible)
        $signature = $Rsa.SignData(
            $fileBytes,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )

        return $signature
    }
    catch {
        Write-Error "Failed to create signature for ${FilePath}: $_"
        return $null
    }
}

function Test-RsaSignature {
    param(
        [System.Security.Cryptography.RSA]$Rsa,
        [string]$FilePath,
        [string]$SignatureFile
    )

    try {
        # Read file data
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)

        # Read signature
        $signature = [System.IO.File]::ReadAllBytes($SignatureFile)

        # Verify signature with SHA256 and PKCS1 padding
        $verified = $Rsa.VerifyData(
            $fileBytes,
            $signature,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )

        return $verified
    }
    catch {
        return $false
    }
}

################################################################################
# File Processing Functions
################################################################################

function Test-ShouldSignFile {
    param(
        [string]$RelativePath
    )

    # Skip if it's the signature generator itself
    if ($RelativePath -eq "_bin\WIN-GitExec-gen_sigs.ps1" -or
        $RelativePath -eq "_bin/WIN-GitExec-gen_sigs.ps1" -or
        (Split-Path -Leaf $RelativePath) -eq "WIN-GitExec-gen_sigs.ps1") {
        return $false
    }

    # Normalize path separators for comparison
    $normalizedPath = $RelativePath -replace '\\', '/'

    # Sign files in scripts directory
    if ($normalizedPath -match "^$([regex]::Escape($ScriptsDir))/.*\.(sh|ps1)$") {
        return $true
    }

    # Sign files in _framework/_library
    if ($normalizedPath -match '^_framework/_library/.*\.(sh|psm1)$') {
        return $true
    }

    # Skip everything else
    return $false
}

function Get-FilesByCategory {
    param(
        [string]$RepoRoot,
        [System.Security.Cryptography.RSA]$RsaPublic
    )

    $newSigs = @()
    $outdatedSigs = @()
    $validSigs = @()
    $invalidSigs = @()
    $fileCount = 0
    $skipCount = 0

    # Find all script files
    $scriptFiles = Get-ChildItem -Path $RepoRoot -Recurse -File -Include *.sh, *.ps1, *.psm1 -ErrorAction SilentlyContinue

    foreach ($file in $scriptFiles) {
        # Get relative path from repo root
        $relativePath = $file.FullName.Substring($RepoRoot.Length + 1)

        # Check if this file should be signed
        if (-not (Test-ShouldSignFile -RelativePath $relativePath)) {
            $skipCount++
            continue
        }

        $fileCount++

        # Create signature path in _sig folder with same structure
        $sigRelativeDir = Split-Path -Parent $relativePath
        $sigDir = Join-Path $RepoRoot "_sig\$sigRelativeDir"
        $sigFile = Join-Path $sigDir "$($file.Name).sig"

        # Check if signature exists and compare modification times
        if (Test-Path $sigFile) {
            $scriptMtime = (Get-Item $file.FullName).LastWriteTime
            $sigMtime = (Get-Item $sigFile).LastWriteTime

            if ($scriptMtime -gt $sigMtime) {
                # Script modified after signature - needs update
                $outdatedSigs += $relativePath
            }
            else {
                # Signature should be current - verify it
                if (Test-RsaSignature -Rsa $RsaPublic -FilePath $file.FullName -SignatureFile $sigFile) {
                    $validSigs += $relativePath
                }
                else {
                    $invalidSigs += $relativePath
                }
            }
        }
        else {
            # No signature exists yet
            $newSigs += $relativePath
        }
    }

    return @{
        NewSigs = $newSigs
        OutdatedSigs = $outdatedSigs
        ValidSigs = $validSigs
        InvalidSigs = $invalidSigs
        FileCount = $fileCount
        SkipCount = $skipCount
    }
}

function Remove-OrphanedSignatures {
    param(
        [string]$RepoRoot
    )

    $sigDir = Join-Path $RepoRoot "_sig"
    if (-not (Test-Path $sigDir)) {
        return 0
    }

    if (-not $script:Quiet -and -not $script:Silent) {
        Write-Host ""
        Write-Host "Checking for orphaned signatures..."
    }

    $orphanCount = 0
    $sigFiles = Get-ChildItem -Path $sigDir -Recurse -File -Filter *.sig -ErrorAction SilentlyContinue

    foreach ($sigFile in $sigFiles) {
        # Get the relative path from _sig\
        $sigRelative = $sigFile.FullName.Substring((Join-Path $RepoRoot "_sig\").Length)

        # Remove .sig extension to get source file path
        $sourceFile = Join-Path $RepoRoot ($sigRelative -replace '\.sig$', '')

        if (-not (Test-Path $sourceFile)) {
            if (-not $script:Quiet -and -not $script:Silent) {
                Write-ColorOutput "Removing orphaned: _sig\$sigRelative" -Color Yellow
            }
            Remove-Item $sigFile.FullName -Force
            $orphanCount++
        }
    }

    if (-not $script:Quiet -and -not $script:Silent) {
        if ($orphanCount -gt 0) {
            Write-Success "Removed $orphanCount orphaned signature(s)"
        }
        else {
            Write-Success "No orphaned signatures found"
        }
    }

    # Clean up empty directories in _sig
    Get-ChildItem -Path $sigDir -Recurse -Directory -ErrorAction SilentlyContinue |
        Where-Object { -not (Get-ChildItem -Path $_.FullName -Recurse -File) } |
        Remove-Item -Force -ErrorAction SilentlyContinue

    return $orphanCount
}

################################################################################
# Main Script
################################################################################

if ($Help) {
    Show-Help
}

# Get script location
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# If script is in _bin folder, repo root is parent; otherwise script IS at repo root
if ((Split-Path -Leaf $ScriptDir) -eq "_bin") {
    $RepoRoot = Split-Path -Parent $ScriptDir
}
else {
    $RepoRoot = $ScriptDir
}

$KeyAccount = $env:USERNAME
$PublicKeyFile = Join-Path $RepoRoot "_key\${KeyService}.pub"

# Header
if (-not $Quiet -and -not $Silent) {
    Write-Host ""
    Write-Host "=========================================="
    Write-Host "  RSA Signature Generator (Windows)"
    Write-Host "=========================================="
    Write-Host ""
}

# Check if public key exists
if (-not (Test-Path $PublicKeyFile)) {
    Write-Error "Public key not found"
    Write-Host ""
    Write-Host "Expected location: $PublicKeyFile"
    Write-Host ""
    Write-Host "Please run WIN-GitExec-gen_rsa_keys.ps1 first to create your signing keys."
    Write-Host ""
    exit 1
}

if (-not $Quiet -and -not $Silent) {
    Write-Success "Found public key: _key\${KeyService}.pub"
    Write-Host ""
}

# Check if private key exists in credential manager
if (-not (Test-CredentialManagerKey -Target $KeyService)) {
    Write-Error "RSA private key not found in credential manager"
    Write-Host ""
    Write-Host "Credential Details:"
    Write-Host "  Service: $KeyService"
    Write-Host "  Account: $KeyAccount"
    Write-Host ""
    Write-Host "Please run WIN-GitExec-gen_rsa_keys.ps1 first to create your signing keys."
    Write-Host ""
    exit 1
}

if (-not $Quiet -and -not $Silent) {
    Write-Success "Found RSA signing key in credential manager"
    Write-Host "  Service: $KeyService"
    Write-Host "  Account: $KeyAccount"
    Write-Host ""
    Write-Host "Working directory: $RepoRoot"
    Write-Host ""
}

# Retrieve private key from credential manager
$privateKeyPem = Get-CredentialManagerKey -Target $KeyService
if (-not $privateKeyPem) {
    Write-Error "Failed to retrieve private key from credential manager"
    Write-Host "You may need to run WIN-GitExec-gen_rsa_keys.ps1 to re-create the key."
    exit 1
}

# Import private key
$rsaPrivate = Import-RsaPrivateKey -PrivateKeyPem $privateKeyPem
if (-not $rsaPrivate) {
    Write-Error "Retrieved key is not a valid RSA private key"
    Write-Host ""
    Write-Host "The key in credential manager may be corrupted or in an incorrect format."
    Write-Host "Please regenerate your keys using WIN-GitExec-gen_rsa_keys.ps1"
    Write-Host ""
    exit 1
}

if (-not $Quiet -and -not $Silent) {
    Write-Success "Private key validated"
}

# Import public key
$publicKeyPem = Get-Content $PublicKeyFile -Raw
$rsaPublic = Import-RsaPublicKey -PublicKeyPem $publicKeyPem
if (-not $rsaPublic) {
    Write-Error "Failed to import public key"
    $rsaPrivate.Dispose()
    exit 1
}

# Clean up orphaned signatures
Remove-OrphanedSignatures -RepoRoot $RepoRoot | Out-Null

if (-not $Quiet -and -not $Silent) {
    Write-Host ""
}

# Scan files and categorize by signature status
$categories = Get-FilesByCategory -RepoRoot $RepoRoot -RsaPublic $rsaPublic

$newSigs = $categories.NewSigs
$outdatedSigs = $categories.OutdatedSigs
$validSigs = $categories.ValidSigs
$invalidSigs = $categories.InvalidSigs
$fileCount = $categories.FileCount
$skipCount = $categories.SkipCount

# Phase 2: Report status
if ($Quiet) {
    # Quiet mode: Simple list format
    foreach ($file in $validSigs) {
        Write-Host "[OK]  $file"
    }
    foreach ($file in $newSigs) {
        Write-Host "[NEW] $file"
    }
    foreach ($file in $outdatedSigs) {
        Write-Host "[OUT] $file"
    }
    foreach ($file in $invalidSigs) {
        Write-Host "[BAD] $file"
    }

    $totalToSign = $newSigs.Count + $outdatedSigs.Count + $invalidSigs.Count
    if ($validSigs.Count -gt 0 -or $totalToSign -gt 0) {
        Write-Host ""
        Write-Host "$($validSigs.Count) valid, $($newSigs.Count) new, $($outdatedSigs.Count) outdated, $($invalidSigs.Count) invalid"
    }
}
elseif (-not $Silent) {
    # Verbose mode: Full status report
    Write-Host "=========================================="
    Write-Host "  Signature Status Report"
    Write-Host "=========================================="
    Write-Host "Files scanned:                  $($fileCount + $skipCount)"
    Write-Host "Files skipped (excluded):       $skipCount"
    Write-Host ""
    Write-ColorOutput "Files with valid signatures:    $($validSigs.Count)  [OK]" -Color Green
    Write-ColorOutput "Files needing new signatures:   $($newSigs.Count)  [NEW]" -Color Cyan
    Write-ColorOutput "Files with outdated signatures: $($outdatedSigs.Count)  [OUT]" -Color Yellow
    if ($invalidSigs.Count -gt 0) {
        Write-ColorOutput "Files with invalid signatures:  $($invalidSigs.Count)  [BAD] ⚠️" -Color Red
    }
    else {
        Write-ColorOutput "Files with invalid signatures:  0  [BAD]" -Color Green
    }
    Write-Host "=========================================="
}

# Calculate total files to sign
$totalToSign = $newSigs.Count + $outdatedSigs.Count + $invalidSigs.Count

# Prepare log file
$logDir = Join-Path $RepoRoot "_logs\gen_sigs"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

$timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$logFile = Join-Path $logDir "${timestamp}.log"

# Write log header
$logHeader = @"
========================================
Signature Generation Log
========================================
Date:       $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
User:       $env:USERNAME
Computer:   $env:COMPUTERNAME
Repository: $RepoRoot

Files Scanned: $($fileCount + $skipCount)
Files Signed:  $totalToSign

Signature Verification Results:
  Valid signatures:    $($validSigs.Count)
  Invalid signatures:  $($invalidSigs.Count)
  Outdated signatures: $($outdatedSigs.Count)
  New files:           $($newSigs.Count)

========================================
Signature Details
========================================

"@

$logHeader | Out-File -FilePath $logFile -Encoding UTF8

# Phase 3: Show what will change and prompt
if ($totalToSign -gt 0) {

    # Check mode: just report status and exit
    if ($Check) {
        if ($Quiet) {
            Write-Host "Check mode: No files were signed"
            Write-Host "Log: _logs\gen_sigs\${timestamp}.log"
        }
        else {
            Write-Host ""
            Write-Info "Check mode: Signature status reported above."
            Write-Host "No files were signed."
            Write-Host "Log saved to:       _logs\gen_sigs\${timestamp}.log"
            Write-Host ""
        }

        # Log check mode
        "`nCHECK MODE: No files were signed.`n" | Out-File -FilePath $logFile -Append -Encoding UTF8
        "Files that need signing:" | Out-File -FilePath $logFile -Append -Encoding UTF8
        foreach ($file in $newSigs) {
            "[NEW] $file" | Out-File -FilePath $logFile -Append -Encoding UTF8
        }
        foreach ($file in $outdatedSigs) {
            "[OUT] $file" | Out-File -FilePath $logFile -Append -Encoding UTF8
        }
        foreach ($file in $invalidSigs) {
            "[BAD] $file" | Out-File -FilePath $logFile -Append -Encoding UTF8
        }

        $rsaPrivate.Dispose()
        $rsaPublic.Dispose()
        exit 0
    }

    if (-not $Quiet -and -not $Silent) {
        Write-Host ""
    }

    # Show warning if invalid signatures detected
    if ($invalidSigs.Count -gt 0 -and -not $Silent) {
        if ($Quiet) {
            Write-Host ""
            Write-Host "WARNING: $($invalidSigs.Count) invalid signature(s) detected"
            Write-Host "Will be re-signed"
            Write-Host ""
        }
        else {
            Write-ColorOutput "⚠️  WARNING: Invalid signatures detected!" -Color Red
            Write-Host ""
            Write-Host "The following files have signatures that DO NOT verify:"
            foreach ($file in $invalidSigs) {
                Write-ColorOutput "  [BAD] $file" -Color Red
            }
            Write-Host ""
            Write-Host "This could indicate:"
            Write-Host "  - Signature file corruption"
            Write-Host "  - Wrong public key being used"
            Write-Host "  - File tampering"
            Write-Host ""
            Write-Host "These files will be re-signed."
            Write-Host ""
        }
    }

    if ($Quiet) {
        # Quiet mode: Simple signing message
        if ($totalToSign -gt 0) {
            Write-Host "Signing $totalToSign file(s)..."
        }
    }
    elseif (-not $Silent) {
        Write-Host "The following files will be signed:"
        Write-Host ""

        foreach ($file in $newSigs) {
            Write-ColorOutput "  [NEW] $file" -Color Cyan
        }

        foreach ($file in $outdatedSigs) {
            $fullPath = Join-Path $RepoRoot $file
            $mtime = (Get-Item $fullPath).LastWriteTime.ToString("yyyy-MM-dd HH:mm")
            Write-ColorOutput "  [OUT] $file (modified: $mtime)" -Color Yellow
        }

        foreach ($file in $invalidSigs) {
            Write-ColorOutput "  [BAD] $file (VERIFICATION FAILED - signature invalid!)" -Color Red
        }
        Write-Host ""
    }

    # Prompt unless force mode or yes mode
    if (-not $Force -and -not $Yes) {
        if (-not (Confirm-Action "Continue and sign $totalToSign file(s)?")) {
            Write-Host ""
            Write-Host "Aborted by user."

            # Log the abort
            "User aborted signing operation.`n" | Out-File -FilePath $logFile -Append -Encoding UTF8
            "Files that would have been signed:" | Out-File -FilePath $logFile -Append -Encoding UTF8
            foreach ($file in $newSigs) {
                "[NEW] $file" | Out-File -FilePath $logFile -Append -Encoding UTF8
            }
            foreach ($file in $outdatedSigs) {
                "[OUT] $file" | Out-File -FilePath $logFile -Append -Encoding UTF8
            }
            foreach ($file in $invalidSigs) {
                "[BAD] $file" | Out-File -FilePath $logFile -Append -Encoding UTF8
            }

            $rsaPrivate.Dispose()
            $rsaPublic.Dispose()
            exit 0
        }
        Write-Host ""
    }
    elseif ($Force) {
        if (-not $Silent -and -not $Quiet) {
            Write-Host "Force mode: Signing $totalToSign file(s) without prompting..."
            Write-Host ""
        }
    }
    elseif ($Yes) {
        if (-not $Silent -and -not $Quiet) {
            Write-Host "Auto-approving: Signing $totalToSign file(s)..."
            Write-Host ""
        }
    }
}
else {
    if ($Quiet) {
        # Quiet mode: simple message
        Write-Host ""
        Write-Host "All signatures valid"
    }
    elseif (-not $Silent) {
        Write-Host ""
        Write-Success "All signatures are valid!"
        Write-Host ""
    }

    # Check mode: just report and exit
    if ($Check) {
        if ($Quiet) {
            Write-Host "Check mode: No files were signed"
            Write-Host "Log: _logs\gen_sigs\${timestamp}.log"
        }
        elseif (-not $Silent) {
            Write-Info "Check mode: All signatures verified successfully."
            Write-Host "Log saved to:       _logs\gen_sigs\${timestamp}.log"
            Write-Host ""
        }

        # Log check mode
        "CHECK MODE: All signatures valid." | Out-File -FilePath $logFile -Append -Encoding UTF8

        $rsaPrivate.Dispose()
        $rsaPublic.Dispose()
        exit 0
    }

    # Log all valid signatures
    "All signatures are valid. No files needed signing.`n" | Out-File -FilePath $logFile -Append -Encoding UTF8
    "Files with valid signatures:" | Out-File -FilePath $logFile -Append -Encoding UTF8
    foreach ($file in $validSigs) {
        "[OK] $file" | Out-File -FilePath $logFile -Append -Encoding UTF8
    }

    if ($Quiet) {
        Write-Host "Log: _logs\gen_sigs\${timestamp}.log"
    }
    elseif (-not $Silent) {
        Write-Host "No changes needed. Exiting."
        Write-Host "Log saved to:       _logs\gen_sigs\${timestamp}.log"
        Write-Host ""
    }

    $rsaPrivate.Dispose()
    $rsaPublic.Dispose()
    exit 0
}

# Phase 4: Generate signatures
if (-not $Quiet -and -not $Silent) {
    Write-Host "Generating signatures..."
    Write-Host ""
}

# Sign files
$signedCount = 0

# Process files needing signatures
$allFilesToSign = $newSigs + $outdatedSigs + $invalidSigs

foreach ($relativePath in $allFilesToSign) {
    $file = Join-Path $RepoRoot $relativePath

    # Create signature directory if needed
    $sigRelativeDir = Split-Path -Parent $relativePath
    $sigDir = Join-Path $RepoRoot "_sig\$sigRelativeDir"
    $sigFile = Join-Path $sigDir "$(Split-Path -Leaf $file).sig"

    if (-not (Test-Path $sigDir)) {
        New-Item -Path $sigDir -ItemType Directory -Force | Out-Null
    }

    # Generate signature
    $signature = New-RsaSignature -Rsa $rsaPrivate -FilePath $file

    if ($signature) {
        # Save signature to file
        [System.IO.File]::WriteAllBytes($sigFile, $signature)

        if ($Quiet) {
            Write-Host "✔ $relativePath"
        }
        elseif (-not $Silent) {
            Write-ColorOutput "✔ $relativePath" -Color Green
        }
        $signedCount++

        # Determine status for log
        if ($newSigs -contains $relativePath) {
            "[NEW] $relativePath" | Out-File -FilePath $logFile -Append -Encoding UTF8
        }
        elseif ($invalidSigs -contains $relativePath) {
            "[BAD] $relativePath (re-signed after verification failure)" | Out-File -FilePath $logFile -Append -Encoding UTF8
        }
        else {
            "[OUT] $relativePath" | Out-File -FilePath $logFile -Append -Encoding UTF8
        }
    }
    else {
        Write-ColorOutput "✗ $relativePath (signing failed)" -Color Red
        "[ERR] $relativePath (signing failed)" | Out-File -FilePath $logFile -Append -Encoding UTF8
    }
}

# Log valid signatures
if ($validSigs.Count -gt 0) {
    "`nFiles with valid signatures (not re-signed):" | Out-File -FilePath $logFile -Append -Encoding UTF8
    foreach ($file in $validSigs) {
        "[OK] $file" | Out-File -FilePath $logFile -Append -Encoding UTF8
    }
}

Write-Host ""
if ($Quiet) {
    Write-Host ""
    Write-Host "Signed: $signedCount files"
    Write-Host "Log: _logs\gen_sigs\${timestamp}.log"
}
elseif (-not $Silent) {
    Write-Host "=========================================="
    Write-Success "Signature generation complete!"
    Write-Host "=========================================="
    Write-Host "Files signed:       $signedCount"
    Write-Host "Log saved to:       _logs\gen_sigs\${timestamp}.log"
    Write-Host ""
    Write-Info "Next steps:"
    Write-Host "  1. Review log file: _logs\gen_sigs\${timestamp}.log"
    Write-Host "  2. Commit _sig\ folder to git"
    Write-Host "  3. Distribute GitExec_RSA.pub with your scripts"
    Write-Host ""
    Write-ColorOutput "Note:" -Color Yellow
    Write-Host " Signature files in _sig\ mirror the directory structure."
    Write-Host "=========================================="
}

# Clean up
$rsaPrivate.Dispose()
$rsaPublic.Dispose()

exit 0
