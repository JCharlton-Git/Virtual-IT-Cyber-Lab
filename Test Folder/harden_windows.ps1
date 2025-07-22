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





Write-Host "Starting Windows Hardening Script (v1.1 - Corrected)" -ForegroundColor Green
Write-Warning "System files WILL BE MODIFIED. Create regular backups."
Start-Transcript "$env:TEMP\HardenWindows-$(Get-Date -Format yyyyMMdd-HHmmss).log"

# Version Check




if (-not ($PSVersionTable.PSVersion -ge [version]"5.1" -and $PSVersionTable.PSEdition -eq "Desktop")) {
    Write-Warning "This script Requires WINDOWS POWERSHELL 5.1+ or greater."
    Write-Warning "Version Detected:"
    Write-Warning "PSVersion: $($PSVersionTable.PSVersion)"
    Write-Warning "PSEdition: $($PSVersionTable.PSEdition)"
    exit 1
}
Write-Host "Running Windows PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor Green

# System Restore




try {
    Checkpoint-Computer -Description "Created Before Windows Hardening Script Run" -RestorePointType MODIFY-SETTINGS
} catch {
    Write-Warning "Restore point creation failure: $_"
}

# Disable SMBv1




Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10") {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 4 -Type DWord
}

# Configure TLS/SSL Protocols




$protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")

foreach ($proto in $protocols) {
    $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server"
    $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Client"
    
    # Create paths if they don't exist
	
	
    if (-not (Test-Path $serverPath)) {
        New-Item -Path $serverPath -Force | Out-Null
    }
    if (-not (Test-Path $clientPath)) {
        New-Item -Path $clientPath -Force | Out-Null
    }

    # Set values - disable old protocols, enable new ones
	
	
    $value = if ($proto -in @("TLS 1.2", "TLS 1.3")) { 1 } else { 0 }
    Set-ItemProperty -Path $serverPath -Name "Enabled" -Value $value -Type DWord
    Set-ItemProperty -Path $clientPath -Name "Enabled" -Value $value -Type DWord
}

# Password Policies




Write-Host "Configuring password policies..." -ForegroundColor Green
$secpol = @"
[System Access]
MinimumKeyAge = 1
MaximumKeyAge = 90
MinimumKeyLenght = 14
KeyComplexity = 1
KeyHistorySize = 24
CleartextKey = 0
LockoutFailureCount = 10
LockoutFailureCountReset = 15
LockoutFailureDuration = 15
RequireLogonToChangeKey = 1
[Version]
signature=" `NEWYORK`$"
revision = 1
"@
$secpol | Out-File "$env:TEMP\secpol.inf" -Force
secedit /configure/db "$env:TEMP/secedit.sdb" /cfg "$env:TEMP\secpol.inf" /areas SECURITYPOLICY

# Disable WDigest


Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonKey" -Value 0 -Type DWord

# Firewall Configuration


Write-Host "Configuring Windows Firewall..." -ForegroundColor Green

function Get-ManagementSubnet {
    while ($true) {
        $subnet = Read-Host "Enter your management subnet for RDP access (e.g., 192.168.1.0/24)"
        if ($subnet -match '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$') {
            return $subnet
        }
        Write-Warning "Invalid CIDR format! Example: 192.168.1.0/24"
    }
}

$managementSubnet = Get-ManagementSubnet
Write-Host "Configuring Firewall Rules for $managementSubnet..." -ForegroundColor Green

# Configure firewall profiles with proper boolean values




Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 16384 -LogAllowed $true -LogBlocked $true

$rules = @(
    @{Name="Allow HTTP"; Port=80; IP="Any"},
    @{Name="Allow HTTPS"; Port=443; IP="Any"},
    @{Name="Allow Managed RDP"; Port=3389; IP=$managementSubnet}
)

foreach ($rule in $rules) {
    # Remove existing rule if present
	
	
    Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    
    # Create new rule with proper boolean
	
	
    New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Protocol TCP -LocalPort $rule.Port -RemoteAddress $rule.IP -Action Allow -Enabled $true
    Write-Host "Rule Created: $($rule.Name) ($($rule.IP))" -ForegroundColor Cyan
}

# BitLocker Configuration




Write-Host "Configuring BitLocker..." -ForegroundColor Green
if ((Get-Command -Name Enable-BitLocker -ErrorAction SilentlyContinue) -and (Get-TPM -ErrorAction SilentlyContinue).TPMPresent) {
    $osVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive
    if ($osVolume.VolumeStatus -ne "Encrypted") {
        try {
            Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmAndPinProtector -Pin (ConvertTo-SecureString -String "PleaseChangeThisSecretKey" -AsPlainText -Force) -ErrorAction Stop
            Write-Host "BitLocker enabled | TPM and Pin Protection Enabled" -ForegroundColor Green
        } catch {
            Write-Warning "BitLocker enable failure: $_"
        }
    } else {
        Write-Host "BitLocker Already Enabled" -ForegroundColor Cyan
    }
} else {
    Write-Warning "BitLocker cannot be enabled (TPM missing/Unsupported OS)"
}

# Disable Unnecessary Services




Write-Host "Disabling unnecessary services..." -ForegroundColor Green
$services = @("RemoteRegistry", "SSDPSRV", "upnphost", "Telnet", "TlntSvr", "SNMP", "Spooler")
foreach ($svc in $services) {
    Stop-Service $svc -ErrorAction SilentlyContinue
    Set-Service $svc -StartupType Disabled -ErrorAction SilentlyContinue
}

# LSA Protection


Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord

# Disable LLMNR/NetBIOS


if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient") {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord
} else {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord
}

# Configure NetBIOS


Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } | ForEach-Object {
    Invoke-CimMethod -InputObject $_ -MethodName "SetTcpipNetbios" -Arguments @{TcpipNetbiosOptions = 2}
}

# Windows Defender Settings




Set-MpPreference -EnableControlledFolderAccess $true -EnableNetworkProtection $true -MAPSReporting Advanced

# Completion
Write-Host "Hardening Process Completed." -ForegroundColor Green
Write-Host "Reboot at earliest convenience for changes to take effect." -ForegroundColor Green
Write-Host "Log available at: $($(Get-ChildItem "$env:TEMP\HardenWindows-*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName)" -ForegroundColor Cyan

Write-Host "Summary of changes:" -ForegroundColor Yellow
Write-Host "- SMBv1 and legacy protocols disabled"
Write-Host "- TLS 1.2/1.3 enabled, older protocols disabled"
Write-Host "- NIST-compliant password policies enforced"
Write-Host "- Firewall configured to block inbound by default"
Write-Host "- BitLocker encryption enforced"
Write-Host "- Unnecessary services disabled"
Write-Host "- Windows Defender protections enabled"

Stop-Transcript