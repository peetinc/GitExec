<#
.SYNOPSIS
  WIN-GitExec-core.psm1
  Core module for GitExec framework

.DESCRIPTION
  Contains all business logic, functions, and execution code
  This file is downloaded and imported by the thin wrapper script

.NOTES
  Copyright (C) 2026 Peet, Inc.
  Licensed under GPLv2
#>

# ====== MODULE VARIABLES ======
$script:ProjectName = 'GitExec'
$script:ProjectVersion = '1.0.1'

$script:SECRET_NAME_PAT = 'GitExecPAT'
$script:SECRET_NAME_RSA = 'GitExecRSA'
$script:BASE_DIR = 'C:\ProgramData\GitExec'
$script:BLOB_PATH_PAT = Join-Path $script:BASE_DIR "$($script:SECRET_NAME_PAT).bin"
$script:BLOB_PATH_RSA = Join-Path $script:BASE_DIR "$($script:SECRET_NAME_RSA).bin"
$script:TEMP_DIR = Join-Path $script:BASE_DIR 'Temp'
$script:LOG_DIR_SYSTEM = Join-Path $script:BASE_DIR 'Logs\System'
$script:LOG_DIR_USER = Join-Path $script:BASE_DIR 'Logs\User'
$script:LOG_DIR_TEMP = Join-Path $script:BASE_DIR 'Logs\Temp'
$script:MACHINE_GUID = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
$script:ENTROPY_PAT = [Text.Encoding]::UTF8.GetBytes("GitExec-ENTRO:$($script:MACHINE_GUID):PAT")
$script:ENTROPY_RSA = [Text.Encoding]::UTF8.GetBytes("GitExec-ENTRO:$($script:MACHINE_GUID):RSA")

# ====== ENTRY POINT FUNCTION ======
function Invoke-GitExecInit {
    [CmdletBinding()]
    param()

    # First convert any Syncro variables
    Convert-Variables
    
    # Build scriptUrl from components if provided
    if ($global:scriptUrlBase -and $global:scriptName) {
        $global:scriptUrlBase = $global:scriptUrlBase.TrimEnd('/')
        $global:scriptName = $global:scriptName.TrimStart('/')
        $global:scriptUrl = "$($global:scriptUrlBase)/$($global:scriptName)"
    }
    elseif ($global:scriptUrlBase -or $global:scriptName) {
        Write-Log -Level ERROR -Message "Both scriptUrlBase and scriptName are required when using URL components"
        Write-Log -Level ERROR -Message "scriptUrlBase: $(if ($global:scriptUrlBase) { $global:scriptUrlBase } else { '(not set)' })"
        Write-Log -Level ERROR -Message "scriptName: $(if ($global:scriptName) { $global:scriptName } else { '(not set)' })"
        exit 1
    }

    # Validate required variables
    if (-not $global:scriptUrl) {
        Write-Log -Level ERROR -Message "scriptUrl is required but not set"
        Write-Log -Level ERROR -Message "Set scriptUrl or both scriptUrlBase and scriptName"
        exit 1
    }

    # SECURITY: Require HTTPS to prevent man-in-the-middle attacks
    if ($global:scriptUrl -notmatch '^https://') {
        Write-Log -Level ERROR -Message "scriptUrl must use HTTPS protocol"
        Write-Log -Level ERROR -Message "Provided URL: $($global:scriptUrl)"
        Write-Log -Level ERROR -Message "HTTP URLs are not allowed for security reasons"
        exit 1
    }

    # Set defaults
    if (-not $global:runAsUser) { $global:runAsUser = $false }
    if (-not $global:useAPI) { $global:useAPI = $false }
    if (-not $global:runAsUserTimeout) { $global:runAsUserTimeout = 600 }

    # Logging defaults
    if (-not $global:loggingMode) { $global:loggingMode = "Full" }
    if (-not $global:logRetentionDays) { $global:logRetentionDays = 30 }

    # Validate loggingMode
    if ($global:loggingMode -notin @("None", "FrameworkOnly", "Full")) {
        Write-Log -Level WARN -Message "Invalid loggingMode '$($global:loggingMode)', defaulting to 'Full'"
        $global:loggingMode = "Full"
    }

    # Run main execution
    Invoke-GitExecMain
}

# ====== VARIABLE CONVERSION ======
function Convert-Variables {
    [CmdletBinding()]
    param()

    $conversionCount = 0
    $variables = Get-Variable -Scope Global

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
                # SECURITY: Do not use Invoke-Expression on user input
                # Extract content between @( and ), split by comma, trim each element
                try {
                    $arrayContent = $trimmedValue -replace '^\@\(\s*', '' -replace '\s*\)$', ''
                    # Handle quoted strings and simple values
                    $elements = @()
                    foreach ($element in ($arrayContent -split ',')) {
                        $element = $element.Trim()
                        # Remove surrounding quotes if present
                        if ($element -match '^[''"](.*)[''""]$') {
                            $element = $matches[1]
                        }
                        if ($element -ne '') {
                            $elements += $element
                        }
                    }
                    if ($elements.Count -gt 0) {
                        $converted = $elements
                    }
                } catch {
                    Write-Host "[Convert-Variables] WARN: Array parsing failed for $($var.Name)"
                    $converted = $null
                }
            }

            if ($null -ne $converted) {
                try {
                    Set-Variable -Name $var.Name -Value $converted -Scope Global
                    $conversionCount++
                } catch {
                    Write-Host "[Convert-Variables] ERROR: Failed to set variable"
                }
            }
        }
    }
}

# ====== HELPER FUNCTIONS ======
function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][ValidateSet("INFO","OK","WARN","ERROR","START","COMPLETE")]
        [string]$Level
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message"
}

function Test-IsSystem {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    return $currentIdentity.IsSystem
}

function Get-AllInteractiveUsers {
    $users = @()
    
    try {
        $explorerProcesses = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'"
        foreach ($process in $explorerProcesses) {
            $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner
            if ($owner.User -and $owner.User -notmatch '^(SYSTEM|DWM-|UMFD-)') {
                $fullName = "$($owner.Domain)\$($owner.User)"
                if ($fullName -notin $users) {
                    $users += $fullName
                }
            }
        }
    } catch {}
    
    try {
        $consoleUser = (Get-CimInstance Win32_ComputerSystem).UserName
        if ($consoleUser -and $consoleUser -notin $users) {
            $users += $consoleUser
        }
    } catch {}
    
    return $users
}

function Ensure-LogDirectories {
    # Create log directories with proper ACLs
    $dirs = @(
        @{Path = $script:LOG_DIR_SYSTEM; Name = "System logs"},
        @{Path = $script:LOG_DIR_USER; Name = "User logs"},
        @{Path = $script:LOG_DIR_TEMP; Name = "Temp logs"; TempDir = $true}
    )

    foreach ($dir in $dirs) {
        if (Test-Path $dir.Path) { continue }

        try {
            New-Item -ItemType Directory -Path $dir.Path -Force | Out-Null

            # Set ACLs
            $acl = New-Object System.Security.AccessControl.DirectorySecurity
            $acl.SetAccessRuleProtection($true, $false)

            # SYSTEM: Full Control
            $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                'SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
            )
            $acl.AddAccessRule($systemRule)

            # Administrators: Full Control
            $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                'BUILTIN\Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
            )
            $acl.AddAccessRule($adminRule)

            # For Temp directory: Users get Modify access
            if ($dir.TempDir) {
                $usersRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    'BUILTIN\Users', 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
                )
                $acl.AddAccessRule($usersRule)
            }

            Set-Acl -Path $dir.Path -AclObject $acl
        } catch {
            Write-Log -Level WARN -Message "Failed to create/secure $($dir.Name): $_"
        }
    }
}

function Cleanup-OldLogs {
    if ($global:loggingMode -eq "None") { return }
    if ($global:logRetentionDays -le 0) { return }

    try {
        $cutoffDate = (Get-Date).AddDays(-$global:logRetentionDays)
        $logDirs = @($script:LOG_DIR_SYSTEM, $script:LOG_DIR_USER)

        foreach ($logDir in $logDirs) {
            if (-not (Test-Path $logDir)) { continue }
            Get-ChildItem $logDir -Filter "*.log" -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt $cutoffDate } |
                Remove-Item -Force -ErrorAction SilentlyContinue
        }
    } catch {}
}

function Cleanup-TempLogs {
    # Sweep temp folder for orphaned *.output.log files and clean up
    try {
        if (-not (Test-Path $script:LOG_DIR_TEMP)) { return }

        Get-ChildItem $script:LOG_DIR_TEMP -Filter "*.output.log" -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
    } catch {}
}

function Ensure-DpapiTypes {
    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
    if (-not ('System.Security.Cryptography.ProtectedData' -as [type])) {
        throw "DPAPI not available on this system"
    }
}

function Unprotect-DpapiSecret {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][byte[]]$EntropyBytes
    )

    if (-not (Test-Path $FilePath)) { return $null }

    Ensure-DpapiTypes
    $encryptedData = [System.IO.File]::ReadAllBytes($FilePath)
    $decryptedBytes = [Security.Cryptography.ProtectedData]::Unprotect(
        $encryptedData, $EntropyBytes, 'LocalMachine')
    return [Text.Encoding]::UTF8.GetString($decryptedBytes)
}

function Get-GitHubPat {
    $token = Unprotect-DpapiSecret -FilePath $script:BLOB_PATH_PAT -EntropyBytes $script:ENTROPY_PAT
    if (-not $token) {
        throw "No stored PAT found at: $($script:BLOB_PATH_PAT)"
    }
    return $token
}

function Get-RSAPublicKey {
    $key = Unprotect-DpapiSecret -FilePath $script:BLOB_PATH_RSA -EntropyBytes $script:ENTROPY_RSA
    if (-not $key) {
        throw "No stored RSA public key found at: $($script:BLOB_PATH_RSA)"
    }
    return $key
}

function Read-ASN1Length {
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

function Import-RSAPublicKeyFromSPKI {
    param([Parameter(Mandatory)][byte[]]$KeyBytes)

    try {
        $offset = 0

        # Read outer SEQUENCE tag and length
        if ($KeyBytes[$offset] -ne 0x30) { throw "Invalid SPKI: expected SEQUENCE at offset 0" }
        $offset++
        $outerLen = Read-ASN1Length -Bytes $KeyBytes -Offset ([ref]$offset)

        # Read algorithm SEQUENCE tag and length
        if ($KeyBytes[$offset] -ne 0x30) { throw "Invalid SPKI: expected algorithm SEQUENCE" }
        $offset++
        $algLen = Read-ASN1Length -Bytes $KeyBytes -Offset ([ref]$offset)

        # Skip algorithm SEQUENCE content
        $offset += $algLen

        # Read BIT STRING tag and length
        if ($KeyBytes[$offset] -ne 0x03) { throw "Invalid SPKI: expected BIT STRING" }
        $offset++
        $bitStringLen = Read-ASN1Length -Bytes $KeyBytes -Offset ([ref]$offset)

        # Skip unused bits indicator
        if ($KeyBytes[$offset] -ne 0x00) {
            Write-Log -Level WARN -Message "BIT STRING has $($KeyBytes[$offset]) unused bits (expected 0)"
        }
        $offset++

        # Now we're at the RSA public key SEQUENCE
        if ($KeyBytes[$offset] -ne 0x30) { throw "Invalid RSA key: expected SEQUENCE" }
        $offset++
        $rsaSeqLen = Read-ASN1Length -Bytes $KeyBytes -Offset ([ref]$offset)

        # Read modulus INTEGER tag and length
        if ($KeyBytes[$offset] -ne 0x02) { throw "Invalid RSA key: expected modulus INTEGER" }
        $offset++
        $modulusLen = Read-ASN1Length -Bytes $KeyBytes -Offset ([ref]$offset)

        # Extract modulus bytes (skip leading 0x00 if present)
        if ($KeyBytes[$offset] -eq 0x00) {
            $offset++
            $modulusLen--
        }
        $modulus = $KeyBytes[$offset..($offset + $modulusLen - 1)]
        $offset += $modulusLen

        # Read exponent INTEGER tag and length
        if ($KeyBytes[$offset] -ne 0x02) { throw "Invalid RSA key: expected exponent INTEGER" }
        $offset++
        $exponentLen = Read-ASN1Length -Bytes $KeyBytes -Offset ([ref]$offset)

        # Extract exponent bytes
        $exponent = $KeyBytes[$offset..($offset + $exponentLen - 1)]

        Write-Log -Level INFO -Message "Parsed RSA key: Modulus=$($modulus.Length) bytes, Exponent=$($exponentLen) bytes"

        # Create RSA parameters
        $rsaParams = New-Object System.Security.Cryptography.RSAParameters
        $rsaParams.Modulus = $modulus
        $rsaParams.Exponent = $exponent

        # Create RSA object and import parameters
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsa.ImportParameters($rsaParams)

        return $rsa

    } catch {
        throw "Failed to parse SPKI format: $_"
    }
}

function Test-ScriptSignature {
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][string]$SignaturePath
    )

    Write-Log -Level INFO -Message "Verifying script signature..."

    if (-not (Test-Path $SignaturePath)) {
        Write-Log -Level ERROR -Message "Signature file not found: $SignaturePath"
        return $false
    }

    try {
        $base64Key = Get-RSAPublicKey
    } catch {
        Write-Log -Level ERROR -Message "Failed to retrieve RSA public key: $_"
        return $false
    }

    Write-Log -Level OK -Message "RSA public key retrieved"

    # Reconstruct PEM format
    $pemKey = "-----BEGIN PUBLIC KEY-----`n"
    for ($i = 0; $i -lt $base64Key.Length; $i += 64) {
        $length = [Math]::Min(64, $base64Key.Length - $i)
        $pemKey += $base64Key.Substring($i, $length) + "`n"
    }
    $pemKey += "-----END PUBLIC KEY-----"

    try {
        $scriptBytes = [System.IO.File]::ReadAllBytes($ScriptPath)
        $signatureBytes = [System.IO.File]::ReadAllBytes($SignaturePath)

        # Convert PEM to bytes
        $pemContent = $pemKey -replace "-----BEGIN PUBLIC KEY-----","" `
                               -replace "-----END PUBLIC KEY-----","" `
                               -replace "\s",""
        $keyBytes = [System.Convert]::FromBase64String($pemContent)

        # Import RSA public key
        $rsa = $null
        $importMethod = [System.Security.Cryptography.RSA].GetMethod('ImportSubjectPublicKeyInfo')

        if ($importMethod) {
            # PowerShell Core / .NET 5+
            Write-Log -Level INFO -Message "Using modern RSA import method (.NET Core/5+)"
            $rsa = [System.Security.Cryptography.RSA]::Create()
            $rsa.ImportSubjectPublicKeyInfo($keyBytes, [ref]$null)
        } else {
            # Windows PowerShell 5.1 / .NET Framework
            Write-Log -Level INFO -Message "Using legacy RSA import method (Windows PowerShell 5.1)"
            $rsa = Import-RSAPublicKeyFromSPKI -KeyBytes $keyBytes
        }

        # Compute SHA256 hash
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($scriptBytes)

        Write-Log -Level INFO -Message "Script hash (SHA256): $([BitConverter]::ToString($hashBytes).Replace('-',''))"
        Write-Log -Level INFO -Message "Signature size: $($signatureBytes.Length) bytes"

        # Verify signature
        if ($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
            # Windows PowerShell / .NET Framework
            Write-Log -Level INFO -Message "Using RSACryptoServiceProvider.VerifyHash"
            $hashAlgOID = [System.Security.Cryptography.CryptoConfig]::MapNameToOID("SHA256")
            $isValid = $rsa.VerifyHash($hashBytes, $hashAlgOID, $signatureBytes)
        } else {
            # PowerShell Core / .NET 5+
            Write-Log -Level INFO -Message "Using RSA.VerifyHash with HashAlgorithmName"
            $isValid = $rsa.VerifyHash($hashBytes, $signatureBytes, 
                [System.Security.Cryptography.HashAlgorithmName]::SHA256, 
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        }

        # Cleanup
        $rsa.Dispose()
        $sha256.Dispose()

        if ($isValid) {
            Write-Log -Level OK -Message "Signature verification PASSED"
            return $true
        } else {
            Write-Log -Level ERROR -Message "Signature verification FAILED"
            return $false
        }

    } catch {
        Write-Log -Level ERROR -Message "Signature verification error: $_"
        return $false
    }
}

function Convert-GitHubToAPIUrl {
    param([Parameter(Mandatory)][string]$Url)
    
    $uri = [Uri]$Url
    if ($uri.Host -ne 'github.com') {
        throw "Only github.com file URLs can be converted to API format."
    }
    
    $segments = $uri.AbsolutePath.Trim('/').Split('/')
    $blobIndex = [Array]::IndexOf($segments, 'blob')
    if ($blobIndex -eq -1) { $blobIndex = [Array]::IndexOf($segments, 'tree') }
    if ($blobIndex -eq -1 -or $segments.Length -lt $blobIndex + 3) {
        throw "URL must contain '/blob/' or '/tree/' followed by a branch or ref."
    }
    
    $owner = $segments[0]
    $repo = $segments[1]
    $pathSegments = $segments[($blobIndex + 2)..($segments.Length - 1)]
    $filePath = $pathSegments -join '/'
    
    return "https://api.github.com/repos/$owner/$repo/contents/$filePath"
}

function Convert-GitHubToRawUrl {
    param([Parameter(Mandatory)][string]$Url)

    $uri = [Uri]$Url

    # Already a raw URL - strip query/fragment and return
    if ($uri.Host -eq 'raw.githubusercontent.com') {
        return $Url.Split('?')[0].Split('#')[0]
    }

    # Validate host
    if ($uri.Host -ne 'github.com') {
        throw "Expected github.com URL, got: $($uri.Host)"
    }

    # Parse path: /owner/repo/blob|tree/ref/path...
    $parts = $uri.AbsolutePath.Trim('/') -split '/'
    if ($parts.Count -lt 5) {
        throw "Invalid GitHub file URL format"
    }

    $owner = $parts[0]
    $repo = $parts[1]
    $urlType = $parts[2]

    if ($urlType -notin @('blob', 'tree')) {
        throw "URL must point to a file (blob) or directory (tree)"
    }

    $ref = $parts[3]
    $filePath = ($parts[4..($parts.Count-1)]) -join '/'

    return "https://raw.githubusercontent.com/$owner/$repo/$ref/$filePath"
}

function Get-PayloadScript {
    param(
        [Parameter(Mandatory)][string]$RemoteScriptUrl,
        [Parameter(Mandatory)][string]$GitHubPAT
    )
    
    # Ensure directories exist
    if (-not (Test-Path $script:BASE_DIR)) {
        New-Item -ItemType Directory -Path $script:BASE_DIR -Force | Out-Null
        
        # Lock down base directory
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            'SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
        )
        $acl.AddAccessRule($systemRule)
        
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            'BUILTIN\Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
        )
        $acl.AddAccessRule($adminRule)
        
        $usersRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            'BUILTIN\Users', 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
        )
        $acl.AddAccessRule($usersRule)
        
        Set-Acl -Path $script:BASE_DIR -AclObject $acl
        Write-Log -Level INFO -Message "Secured base directory: $($script:BASE_DIR)"
    }
    
    if (-not (Test-Path $script:TEMP_DIR)) {
        New-Item -ItemType Directory -Path $script:TEMP_DIR -Force | Out-Null
        Write-Log -Level INFO -Message "Created temp directory: $($script:TEMP_DIR)"
    }
    
    # Clean up old scripts (older than 1 hour)
    try {
        Get-ChildItem $script:TEMP_DIR -Filter "*.ps1" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-1) } |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Get-ChildItem $script:TEMP_DIR -Filter "*.sig" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-1) } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    } catch {}

    $guid = [System.Guid]::NewGuid().ToString()
    $DownloadPath = Join-Path $script:TEMP_DIR "$guid.ps1"
    $SignaturePath = "$DownloadPath.sig"

    # Construct signature URL
    $SignatureUrl = ""
    if ($RemoteScriptUrl -like "*api.github.com*") {
        $SignatureUrl = $RemoteScriptUrl -replace "/contents/", "/contents/_sig/"
        $SignatureUrl = "$SignatureUrl.sig"
    } else {
        if ($RemoteScriptUrl -match '^(https://raw\.githubusercontent\.com/[^/]+/[^/]+/[^/]+/)(.+)$') {
            $base = $matches[1]
            $path = $matches[2]
            $SignatureUrl = "${base}_sig/${path}.sig"
        } else {
            Write-Log -Level ERROR -Message "Unable to parse URL for signature: $RemoteScriptUrl"
            return $null
        }
    }

    Write-Log -Level INFO -Message "Script download URL: $RemoteScriptUrl"
    Write-Log -Level INFO -Message "Signature download URL: $SignatureUrl"

    try {
        # Download script
        if ($RemoteScriptUrl -like "*api.github.com*") {
            $Headers = @{
                Authorization = "Bearer $GitHubPAT"
                Accept = "application/vnd.github.v3.raw"
                'User-Agent' = "$($script:ProjectName)/$($script:ProjectVersion)"
            }
            Write-Log -Level INFO -Message "Downloading from GitHub API (cache-bypass)"
            Invoke-WebRequest -Uri $RemoteScriptUrl -Headers $Headers -OutFile $DownloadPath -ErrorAction Stop
        } else {
            $Headers = @{
                Authorization = "Bearer $GitHubPAT"
                'User-Agent' = "$($script:ProjectName)/$($script:ProjectVersion)"
            }
            Write-Log -Level INFO -Message "Downloading script"
            Invoke-WebRequest -Uri $RemoteScriptUrl -Headers $Headers -OutFile $DownloadPath -ErrorAction Stop
        }

        Write-Log -Level OK -Message "Downloaded to: $DownloadPath"

        # Download signature
        Write-Log -Level INFO -Message "Downloading signature"
        if ($RemoteScriptUrl -like "*api.github.com*") {
            $SigHeaders = @{
                Authorization = "Bearer $GitHubPAT"
                Accept = "application/vnd.github.v3.raw"
                'User-Agent' = "$($script:ProjectName)/$($script:ProjectVersion)"
            }
            Invoke-WebRequest -Uri $SignatureUrl -Headers $SigHeaders -OutFile $SignaturePath -ErrorAction Stop
        } else {
            $SigHeaders = @{
                Authorization = "Bearer $GitHubPAT"
                'User-Agent' = "$($script:ProjectName)/$($script:ProjectVersion)"
            }
            Invoke-WebRequest -Uri $SignatureUrl -Headers $SigHeaders -OutFile $SignaturePath -ErrorAction Stop
        }

        Write-Log -Level OK -Message "Downloaded signature to: $SignaturePath"
        return $DownloadPath

    } catch {
        Write-Log -Level ERROR -Message "Download failed: $_"
        if (Test-Path $DownloadPath) { Remove-Item $DownloadPath -Force -ErrorAction SilentlyContinue }
        if (Test-Path $SignaturePath) { Remove-Item $SignaturePath -Force -ErrorAction SilentlyContinue }
        return $null
    }
}

# ====== EXECUTION FUNCTIONS ======
function Invoke-ScriptAsSystem {
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][string]$Timestamp,
        [Parameter(Mandatory)][string]$ScriptName
    )

    $scriptExitCode = 0

    try {
        Write-Log -Level INFO -Message "Executing $ScriptName as SYSTEM"
        Write-Host "============================================="
        Write-Host "     $($script:ProjectName) v$($script:ProjectVersion)"
        Write-Host "     SCRIPT: $ScriptName"
        Write-Host "============================================="
        Write-Host "============BEGIN SCRIPT OUTPUT============="

        # If Full logging mode, capture output to dedicated file
        if ($global:loggingMode -eq "Full") {
            $outputLog = Join-Path $script:LOG_DIR_SYSTEM "${Timestamp}_${ScriptName}.output.log"

            # Use cmd.exe for reliable output redirection (all streams)
            $cmd = "cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" > `"$outputLog`" 2>&1"
            $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $cmd -Wait -PassThru -NoNewWindow
            $scriptExitCode = $process.ExitCode

            # Display captured output
            if (Test-Path $outputLog) {
                Get-Content $outputLog | Write-Host
            }
        } else {
            # FrameworkOnly or None - just run and display
            & $ScriptPath | Out-Default
            $scriptExitCode = $LASTEXITCODE
            if ($null -eq $scriptExitCode) { $scriptExitCode = 0 }
        }

    } catch {
        Write-Log -Level ERROR -Message "Error: $_"
        $scriptExitCode = 1
    } finally {
        Write-Host "=============END SCRIPT OUTPUT=============="
        Write-Log -Level INFO -Message "Script completed with exit code: $scriptExitCode"
    }

    return $scriptExitCode
}

function Invoke-ScriptAsUsers {
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][string]$Timestamp,
        [Parameter(Mandatory)][string]$ScriptName
    )

    $allUsers = Get-AllInteractiveUsers
    if ($allUsers.Count -eq 0) {
        throw "runAsUser=`$true but no interactive users are logged in."
    }

    Write-Log -Level INFO -Message "Found $($allUsers.Count) logged-in user(s): $($allUsers -join ', ')"

    $successCount = 0
    $taskJobs = @()

    foreach ($interactiveUser in $allUsers) {
        Write-Log -Level INFO -Message "Creating task for: $interactiveUser"

        try {
            $userSafe = $interactiveUser.Replace('\', '_').Replace(' ', '_')
            $taskName = "GitExec_Payload_$userSafe"

            # Get user's profile path via SID registry lookup (bulletproof method)
            try {
                $userSid = (New-Object System.Security.Principal.NTAccount($interactiveUser)).Translate(
                    [System.Security.Principal.SecurityIdentifier]).Value
                $profilePath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$userSid" -ErrorAction Stop).ProfileImagePath
            } catch {
                Write-Log -Level WARN -Message "Could not resolve profile path for $interactiveUser via SID, skipping"
                continue
            }

            # Create per-user directory in user's AppData\Local
            $userDir = Join-Path $profilePath "AppData\Local\GitExec"
            if (-not (Test-Path $userDir)) {
                New-Item -ItemType Directory -Path $userDir -Force | Out-Null
            }
            $userScriptGuid = [System.Guid]::NewGuid().ToString()
            $userScriptPath = Join-Path $userDir "$userScriptGuid.ps1"
            Copy-Item -Path $ScriptPath -Destination $userScriptPath -Force
            Write-Log -Level INFO -Message "Copied script for $interactiveUser to: $userScriptPath"

            # Create temp log file if Full logging mode
            $tempLogGuid = $null
            $tempLogPath = $null
            if ($global:loggingMode -eq "Full") {
                $tempLogGuid = [System.Guid]::NewGuid().ToString()
                $tempLogPath = Join-Path $script:LOG_DIR_TEMP "$tempLogGuid.output.log"
            }

            # Build task command with output redirection if needed (using user-specific script path)
            if ($global:loggingMode -eq "Full") {
                $taskCmd = "cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$userScriptPath`" > `"$tempLogPath`" 2>&1"
            } else {
                $taskCmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$userScriptPath`""
            }

            $createResult = schtasks /Create /F /TN $taskName /TR $taskCmd /SC ONCE /ST 00:00 /SD 01/01/2000 /RU $interactiveUser /RL LIMITED 2>&1

            if ($LASTEXITCODE -eq 0) {
                schtasks /Run /TN $taskName 2>&1 | Out-Null

                $taskJobs += @{
                    TaskName = $taskName
                    User = $interactiveUser
                    UserSafe = $userSafe
                    TempLogPath = $tempLogPath
                    UserScriptPath = $userScriptPath
                }

                Write-Log -Level OK -Message "Task started for: $interactiveUser"
                $successCount++
            } else {
                Write-Log -Level WARN -Message "Task creation failed for: $interactiveUser"
                # Cleanup user script on failure
                Remove-Item -Path $userScriptPath -Force -ErrorAction SilentlyContinue
            }

        } catch {
            Write-Log -Level WARN -Message "Failed for $interactiveUser : $_"
        }
    }
    
    if ($successCount -eq 0) {
        throw "Failed to create tasks for any users"
    }
    
    Write-Log -Level INFO -Message "Created tasks for $successCount user(s)"
    
    # Monitor completion
    $maxWait = $global:runAsUserTimeout
    $elapsed = 0
    $allCompleted = $false
    
    Write-Log -Level INFO -Message "Monitoring task completion (max wait: $maxWait seconds)..."
    
    while ($elapsed -lt $maxWait -and -not $allCompleted) {
        $allCompleted = $true
        foreach ($job in $taskJobs) {
            $queryResult = schtasks /Query /TN $job.TaskName /FO LIST 2>&1 | Out-String
            if ($queryResult -match "Status:\s+(.+)") {
                $status = $matches[1].Trim()
                if ($status -ne "Ready") {
                    $allCompleted = $false
                    break
                }
            }
        }
        
        if (-not $allCompleted) {
            Start-Sleep -Seconds 5
            $elapsed += 5
        }
    }
    
    if ($allCompleted) {
        Write-Log -Level OK -Message "All user tasks completed"
    } else {
        Write-Log -Level WARN -Message "Some tasks may still be running after timeout"
    }

    # Move temp logs to User directory and display output
    if ($global:loggingMode -eq "Full") {
        foreach ($job in $taskJobs) {
            if ($job.TempLogPath -and (Test-Path $job.TempLogPath)) {
                try {
                    # Build final log filename with username
                    $finalLogName = "${Timestamp}_${ScriptName}_$($job.UserSafe).output.log"
                    $finalLogPath = Join-Path $script:LOG_DIR_USER $finalLogName

                    # Move temp log to User directory
                    Move-Item -Path $job.TempLogPath -Destination $finalLogPath -Force

                    Write-Log -Level INFO -Message "Moved output log for $($job.User) to: $finalLogName"

                    # Display the output
                    Write-Host "============================================="
                    Write-Host "     OUTPUT FROM: $($job.User)"
                    Write-Host "============================================="
                    Write-Host "============BEGIN SCRIPT OUTPUT============="
                    Get-Content $finalLogPath | Write-Host
                    Write-Host "=============END SCRIPT OUTPUT=============="
                } catch {
                    Write-Log -Level WARN -Message "Failed to move log for $($job.User): $_"
                }
            }
        }

        # Clean up any orphaned temp logs
        Cleanup-TempLogs
    }

    # Check exit codes
    Write-Log -Level INFO -Message "Checking task exit codes..."
    $worstExitCode = 0
    $hasExitOne = $false
    
    foreach ($job in $taskJobs) {
        $taskInfo = schtasks /Query /TN $job.TaskName /FO LIST /V 2>&1 | Out-String
        if ($taskInfo -match "Last Result:\s+(\d+)") {
            $exitCode = [int]$matches[1]
            
            if ($exitCode -eq 1) {
                $hasExitOne = $true
                Write-Log -Level ERROR -Message "Task for $($job.User): ERROR (exit code: 1)"
            } elseif ($exitCode -eq 0) {
                Write-Log -Level OK -Message "Task for $($job.User): SUCCESS (exit code: 0)"
            } else {
                Write-Log -Level ERROR -Message "Task for $($job.User): FAILURE (exit code: $exitCode)"
                if ($exitCode -gt $worstExitCode) {
                    $worstExitCode = $exitCode
                }
            }
        } else {
            Write-Log -Level WARN -Message "Task for $($job.User): Could not determine exit code"
        }
    }
    
    # Cleanup tasks and per-user scripts
    foreach ($job in $taskJobs) {
        try { schtasks /Delete /F /TN $job.TaskName 2>&1 | Out-Null } catch {}
        # Cleanup per-user script
        if ($job.UserScriptPath -and (Test-Path $job.UserScriptPath)) {
            Remove-Item -Path $job.UserScriptPath -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Log -Level INFO -Message "Task cleanup completed"
    
    if ($hasExitOne) {
        Write-Log -Level ERROR -Message "At least one task exited with code 1, returning exit code: 1"
        return 1
    } elseif ($worstExitCode -gt 0) {
        Write-Log -Level WARN -Message "Returning worst exit code: $worstExitCode"
        return $worstExitCode
    } else {
        Write-Log -Level OK -Message "All tasks succeeded, returning exit code: 0"
        return 0
    }
}

# ====== MAIN EXECUTION ======
function Invoke-GitExecMain {
    [CmdletBinding()]
    param()

    if (-not (Test-IsSystem)) {
        Write-Log -Level ERROR -Message "$($script:ProjectName) must be run as SYSTEM"
        exit 1
    }

    # Setup logging infrastructure
    if ($global:loggingMode -ne "None") {
        Ensure-LogDirectories
        Cleanup-OldLogs
    }

    # Create timestamp and script name
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $scriptName = Split-Path $global:scriptUrl -Leaf

    # Determine log directory based on execution mode
    $logDir = if ($global:runAsUser) { $script:LOG_DIR_USER } else { $script:LOG_DIR_SYSTEM }

    # Start transcript if logging enabled
    if ($global:loggingMode -ne "None") {
        $transcriptLog = Join-Path $logDir "${timestamp}_${scriptName}.log"
        try {
            Start-Transcript -Path $transcriptLog -Force | Out-Null
        } catch {
            Write-Host "[WARN] Failed to start transcript logging: $_"
        }
    }

    Write-Log -Level START -Message "$($script:ProjectName) v$($script:ProjectVersion) starting"
    if ($global:loggingMode -ne "None") {
        Write-Log -Level INFO -Message "Logging mode: $($global:loggingMode)"
        Write-Log -Level INFO -Message "Transcript log: $transcriptLog"
    }
    Write-Log -Level INFO -Message "Target script: $scriptName"

    # Convert URL
    Write-Log -Level INFO -Message "Source scriptUrl: $($global:scriptUrl)"
    if ($global:useAPI) {
        Write-Log -Level INFO -Message "Using GitHub API (cache-bypass mode)"
        $RemoteScriptUrl = Convert-GitHubToAPIUrl $global:scriptUrl
        Write-Log -Level INFO -Message "API URL: $RemoteScriptUrl"
    } else {
        Write-Log -Level INFO -Message "Converting GitHub URL to raw format"
        $RemoteScriptUrl = Convert-GitHubToRawUrl $global:scriptUrl
        Write-Log -Level OK -Message "URL conversion successful"
        Write-Log -Level INFO -Message "Raw URL: $RemoteScriptUrl"
    }

    try {
        # Get PAT and download script
        $GitHubPAT = Get-GitHubPat
        $ScriptPath = Get-PayloadScript -RemoteScriptUrl $RemoteScriptUrl -GitHubPAT $GitHubPAT

        # SECURITY: Clear PAT from memory immediately after download
        $GitHubPAT = $null
        Remove-Variable -Name GitHubPAT -ErrorAction SilentlyContinue

        if (-not $ScriptPath) {
            throw "Failed to download script"
        }

        # Verify signature
        $SignaturePath = "$ScriptPath.sig"
        Write-Log -Level INFO -Message "========================================"
        Write-Log -Level INFO -Message "SECURITY: Verifying script signature"
        Write-Log -Level INFO -Message "========================================"

        $signatureValid = Test-ScriptSignature -ScriptPath $ScriptPath -SignaturePath $SignaturePath

        if (-not $signatureValid) {
            Write-Log -Level ERROR -Message "========================================"
            Write-Log -Level ERROR -Message "SECURITY ALERT: Signature verification failed"
            Write-Log -Level ERROR -Message "========================================"
            Write-Log -Level ERROR -Message "REFUSING TO EXECUTE for security reasons"

            Remove-Item -Path $ScriptPath -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $SignaturePath -Force -ErrorAction SilentlyContinue

            throw "Signature verification failed"
        }

        Write-Log -Level OK -Message "========================================"
        Write-Log -Level OK -Message "SECURITY: Script verified - safe to execute"
        Write-Log -Level OK -Message "========================================"

        if ($global:runAsUser) {
            Write-Log -Level INFO -Message "Run as user mode: Executing $scriptName for all logged-in users"
            $exitCode = Invoke-ScriptAsUsers -ScriptPath $ScriptPath -Timestamp $timestamp -ScriptName $scriptName
        } else {
            Write-Log -Level INFO -Message "Run as SYSTEM mode: Executing $scriptName"
            $exitCode = Invoke-ScriptAsSystem -ScriptPath $ScriptPath -Timestamp $timestamp -ScriptName $scriptName

            if ($exitCode -eq 0) {
                Write-Log -Level OK -Message "$scriptName completed successfully (exit code: 0)"
            } else {
                Write-Log -Level WARN -Message "$scriptName completed with exit code: $exitCode"
            }
        }
        
        # Cleanup
        if (Test-Path $ScriptPath) {
            Remove-Item -Path $ScriptPath -Force
            Write-Log -Level INFO -Message "Cleaned up downloaded script"
        }
        if (Test-Path $SignaturePath) {
            Remove-Item -Path $SignaturePath -Force
            Write-Log -Level INFO -Message "Cleaned up signature file"
        }

        Write-Log -Level COMPLETE -Message "$($script:ProjectName) execution finished"

        # Stop transcript
        if ($global:loggingMode -ne "None") {
            try { Stop-Transcript | Out-Null } catch {}
        }

        exit $exitCode

    } catch {
        Write-Log -Level ERROR -Message "$($script:ProjectName) error: $($_.Exception.Message)"

        # SECURITY: Ensure PAT is cleared on error
        $GitHubPAT = $null
        Remove-Variable -Name GitHubPAT -ErrorAction SilentlyContinue

        # Cleanup on error
        if ($ScriptPath -and (Test-Path $ScriptPath)) {
            Remove-Item -Path $ScriptPath -Force -ErrorAction SilentlyContinue
        }
        if ($SignaturePath -and (Test-Path $SignaturePath)) {
            Remove-Item -Path $SignaturePath -Force -ErrorAction SilentlyContinue
        }

        # Stop transcript
        if ($global:loggingMode -ne "None") {
            try { Stop-Transcript | Out-Null } catch {}
        }

        exit 1
    }
}

# Export the main function
Export-ModuleMember -Function Invoke-GitExecInit