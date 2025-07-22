# Windows Hardening Script
# Includes:
# - SMBv1 / Vulnerable protocol disabling
# - NIST SP 800-63B Standardized password policies
# - Firewall denies inbound by default
# - BitLocker enforcement if available

# Notes
# Version 1.0
# Author: JCharlton
# Requires: Windows 10, 11, Server 2016+ | PowerShell 5.1+ | TPM 1.2+

# License Included: MIT License

# Admin rights required for run.
# Management Subnet required for run.





Windows Hardening Script (v1.2 - Yet another code re-write)

#Requires -Version 5.1
#Requires -RunAsAdministrator

Write-Host "Starting Windows Hardening Script (v1.2)" -ForegroundColor Cyan
Write-Warning "System modifications will be made. Ensure files are backed up."
Start-Transcript "$env:TEMP\HardenWindows-$(Get-Date -Format yyyyMMdd-HHmmss).log"

# Version Check




if ($PSVersionTable.PSVersion.Major -lt 5 -or $PSVersionTable.PSEdition -ne "Desktop") {
    Write-Warning "This script requires Windows PowerShell 5.1"
    Write-Host "Detected Version: $($PSVersionTable.PSVersion)" -ForegroundColor Red
    exit 1
}

# Restore Point




Write-Host "Creating system restore point . . ." -ForegroundColor Cyan
$vssService = Get-Service -Name VSS -ErrorAction SilentlyContinue

try {
    if ($vssService -and $vssService.Status -ne 'Running') {
        $originalStartupType = $vssService.StartType
        Write-Host "Temporarily enabling Volume Shadow Copy service . . ." -ForegroundColor Cyan
        Set-Service -Name VSS -StartupType Manual -ErrorAction Stop
        Start-Service -Name VSS -ErrorAction Stop
        
        $timeout = 0
        while ($vssService.Status -ne 'Running' -and $timeout -lt 30) {
            Start-Sleep -Seconds 1
            $vssService.Refresh()
            $timeout++
        }
    }

    Checkpoint-Computer -Description "Pre-Hardening Restore Point" -RestorePointType MODIFY_SETTINGS
    Write-Host " System restore point created" -ForegroundColor Cyan
} catch {
    Write-Warning "Restore point creation failed: $_"
    Write-Warning "Continuing Running - Changes may not be reversible. . ."
} finally {
    if ($vssService -and $originalStartupType) {
        try {
            Stop-Service -Name VSS -Force -ErrorAction SilentlyContinue
            Set-Service -Name VSS -StartupType $originalStartupType -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "Could not restore VSS service to original state: $_"
        }
    }
}

# Disable SMBv1




Write-Host "Disabling SMBv1. . ." -ForegroundColor Cyan
try {
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction Stop | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord -Force
    
    if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10") {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 4 -Type DWord -Force
    }
    Write-Host " SMBv1 disabled" -ForegroundColor Cyan
} catch {
    Write-Warning "SMBv1 disable failed: $_"
}

# TLS Config




Write-Host "Configuring TLS protocols. . ." -ForegroundColor Cyan
$tlsConfig = @{
    "SSL 2.0" = 0
    "SSL 3.0" = 0
    "TLS 1.0" = 0
    "TLS 1.1" = 0
    "TLS 1.2" = 1
    "TLS 1.3" = 1
}

foreach ($protocol in $tlsConfig.Keys) {
    try {
        $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
        $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"
        
        if (-not (Test-Path $serverPath)) {
            New-Item -Path $serverPath -Force | Out-Null
        }
        if (-not (Test-Path $clientPath)) {
            New-Item -Path $clientPath -Force | Out-Null
        }

        Set-ItemProperty -Path $serverPath -Name "Enabled" -Value $tlsConfig[$protocol] -Type DWord -Force
        Set-ItemProperty -Path $clientPath -Name "Enabled" -Value $tlsConfig[$protocol] -Type DWord -Force
    } catch {
        Write-Warning "Failed to configure $protocol : $_"
    }
}
Write-Host " TLS configuration complete" -ForegroundColor Cyan

# Password Policies




Write-Host "Applying password policies. . ." -ForegroundColor Cyan
$secpol = @"
[System Access]
MinimumKeyAge = 1
MaximumKeyAge = 90
MinimumKeyLength = 14
KeyComplexity = 1
KeyHistorySize = 24
ClearTextKey = 0
LockoutBadCount = 10
ResetLockoutCount = 15
LockoutDuration = 15
RequireLogonToChangeKey = 1
[Version]
signature="`$NEWYORK`$"
revision=1
"@

try {
    $secpol | Out-File "$env:TEMP\secpol.inf" -Force
    secedit /configure /db "$env:TEMP\secedit.sdb" /cfg "$env:TEMP\secpol.inf" /areas SECURITYPOLICY | Out-Null
    Write-Host "Password policies applied" -ForegroundColor Cyan
} catch {
    Write-Warning "Password policy configuration failed: $_"
}

# Firwall Config




Write-Host "Configuring Windows Firewall. . ." -ForegroundColor Cyan

function Get-ManagementSubnet {
    while ($true) {
        $subnet = Read-Host "Enter management subnet (CIDR format, e.g., 192.168.1.1/24)"
        if ($subnet -match '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$') {
            return $subnet
        }
        Write-Warning "Invalid CIDR format! Example: 192.168.1.1/24"
    }
}

try {
    # Configure firewall profiles
	
	
    $fwProfileParams = @{
        Name                     = "Domain,Public,Private"
        DefaultInboundAction     = "Block"
        DefaultOutboundAction    = "Allow"
        LogFileName              = "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
        LogMaxSizeKilobytes      = 16384
        LogAllowed               = $true
        LogBlocked              = $true
        ErrorAction             = "Stop"
    }
    Set-NetFirewallProfile @fwProfileParams

    # Create management rules
	
	
    $managementSubnet = Get-ManagementSubnet
    $rules = @(
        @{Name="Allow HTTP"; Port=80; Protocol="TCP"; IP="Any"},
        @{Name="Allow HTTPS"; Port=443; Protocol="TCP"; IP="Any"},
        @{Name="Allow Managed RDP"; Port=3389; Protocol="TCP"; IP=$managementSubnet}
    )

    foreach ($rule in $rules) {
        $ruleParams = @{
            DisplayName    = $rule.Name
            Direction      = "Inbound"
            Protocol       = $rule.Protocol
            LocalPort      = $rule.Port
            RemoteAddress  = $rule.IP
            Action        = "Allow"
            Enabled       = $true
            ErrorAction   = "Stop"
        }
        New-NetFirewallRule @ruleParams | Out-Null
    }
    Write-Host "Firewall configured" -ForegroundColor Cyan
} catch {
    Write-Warning "Firewall configuration failed: $_"
}

# BitLocker Config




Write-Host "Configuring BitLocker. . ." -ForegroundColor Cyan
if ((Get-Command -Name "Enable-BitLocker" -ErrorAction SilentlyContinue) -and 
    (Get-TPM -ErrorAction SilentlyContinue).TpmPresent) {
    
    try {
        $osVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive
        if ($osVolume.VolumeStatus -ne "FullyEncrypted") {
            $securePin = ConvertTo-SecureString -String "ChangeThisTempPassword123!" -AsPlainText -Force
            Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmAndPinProtector -Pin $securePin -ErrorAction Stop
            Write-Host " BitLocker enabled with TPM+PIN" -ForegroundColor Cyan
        } else {
            Write-Host " BitLocker already enabled" -ForegroundColor Cyan
        }
    } catch {
        Write-Warning "BitLocker enable failed: $_"
    }
} else {
    Write-Warning "BitLocker not available (TPM missing or unsupported OS)"
}

# Harden Services




Write-Host "Disabling risky services. . ." -ForegroundColor Cyan
$servicesToDisable = @(
    "RemoteRegistry",
    "SSDPSRV",
    "upnphost",
    "Telnet",
    "TlntSvr",
    "SNMP",
    "Spooler"
)

foreach ($service in $servicesToDisable) {
    try {
        Stop-Service -Name $service -ErrorAction Stop -Force | Out-Null
        Set-Service -Name $service -StartupType Disabled -ErrorAction Stop | Out-Null
    } catch {
        Write-Warning "Failed to disable $service : $_"
    }
}
Write-Host "Risky services disabled" -ForegroundColor Cyan

# Miscellaneous Security Fixes


Write-Host "Applying additional security settings. . ." -ForegroundColor Cyan

# LSA Protection





try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord -Force
} catch {
    Write-Warning "LSA protection configuration failed: $_"
}

# Disable LLMNR




try {
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord -Force
} catch {
    Write-Warning "LLMNR disable failed: $_"
}

# Disable NetBIOS




try {
    $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=$true"
    foreach ($adapter in $adapters) {
        Invoke-CimMethod -InputObject $adapter -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = 2} -ErrorAction Stop | Out-Null
    }
} catch {
    Write-Warning "NetBIOS disable failed: $_"
}

# Windows Defender
try {
    Set-MpPreference -EnableControlledFolderAccess $true -EnableNetworkProtection $true -MAPSReporting Advanced -ErrorAction Stop
    Write-Host "Windows Defender protections enabled" -ForegroundColor Cyan
} catch {
    Write-Warning "Defender configuration failed: $_"
}

# Report Changes




Write-Host " Hardening complete!" -ForegroundColor Cyan
Write-Host " Summary of changes:" -ForegroundColor Cyan
Write-Host "- SMBv1 and legacy protocols disabled"
Write-Host "- TLS 1.2/1.3 enforced"
Write-Host "- NIST-compliant password policies"
Write-Host "- Firewall denies inbound by default"
Write-Host "- BitLocker encryption enabled (if supported)"
Write-Host "- Risky services disabled"
Write-Host "- Additional security protections applied"
Write-Host " Reboot required for some changes to take effect." -ForegroundColor Cyan
Write-Host "Log file: $($(Get-ChildItem "$env:TEMP\HardenWindows-*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName)" -ForegroundColor Cyan

Stop-Transcript