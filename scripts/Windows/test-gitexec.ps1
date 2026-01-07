<#
.SYNOPSIS
    test-gitexec.ps1 - Simple test script to verify GitExec implementation

.DESCRIPTION
    Writes system information to console and log file to verify GitExec is working.

.NOTES
    Copyright (C) 2026 Peet, Inc. - Licensed under GPLv2
#>

$LogFile = "$env:TEMP\gitexec-test.log"
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Function to log and echo
function Write-Log {
    param([string]$Message)
    Write-Host $Message
    "[$Timestamp] $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

# Append to log (create if doesn't exist)
"=== GitExec Test Run: $Timestamp ===" | Out-File -FilePath $LogFile -Append -Encoding UTF8

Write-Log "GitExec Test Script - Windows"
Write-Log "=============================="

# Hostname
$Hostname = $env:COMPUTERNAME
Write-Log "Hostname: $Hostname"

# Machine GUID (from registry)
try {
    $MachineGuid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
} catch {
    $MachineGuid = "N/A"
}
Write-Log "Machine GUID: $MachineGuid"

# Primary IP address (first non-loopback IPv4)
try {
    $PrimaryIP = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
        Sort-Object -Property InterfaceIndex |
        Select-Object -First 1).IPAddress

    if (-not $PrimaryIP) {
        # Fallback method
        $PrimaryIP = (Test-Connection -ComputerName $env:COMPUTERNAME -Count 1).IPV4Address.IPAddressToString
    }
} catch {
    $PrimaryIP = "N/A"
}
Write-Log "Primary IP: $PrimaryIP"

# Additional info
Write-Log ""
Write-Log "Additional Info:"
Write-Log "  OS: $([Environment]::OSVersion.VersionString)"
Write-Log "  User: $env:USERNAME"
Write-Log "  Domain: $env:USERDOMAIN"
Write-Log "  PWD: $(Get-Location)"
Write-Log "  Date: $(Get-Date)"

# Execution context
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$IsSystem = ([Security.Principal.WindowsIdentity]::GetCurrent()).IsSystem
Write-Log "  Running as Admin: $IsAdmin"
Write-Log "  Running as SYSTEM: $IsSystem"

Write-Log ""
Write-Log "=============================="
Write-Log "GitExec test completed successfully!"
Write-Log "Log written to: $LogFile"

exit 0
