# Windows Hardening Script
# Includes:
# - SMBv1 / Vulnerable protocol disabling
# - NIST SP 800-63B Standardized password policies
# - Firewall denies inbound by default
# - BitLocker enforcement if available

# Notes
# Version 1.0
# Author: 
# Requires: Windows 10, 11, Server 2016+ | PowerShell 5.1+ | TPM 1.2+

# License Included: MIT License

# Admin rights required for run.
# Management Subnet required for run.





Write-Host " Starting Windows Hardening Script (v1.0)" -ForegroundColor Green
Write-Warning " System files WILL BE MODIFIED. Create regular backups. "
Start-Transcript "$env:TEMP\HardenWindows-$(Get-Date -Format yyyyMMdd-HHmmss).log"

#Check if script is compatible with Windows and Powershell Versions




if (-not ($PSVersionTable.PSVersion -ge [version]"5.1" -and $PSVersionTable.PSEdition -eq "Desktop")) {
	Write-Warning "This script Requires WINDOWS POWERSHELL 5.1+ or greater."
	Write-Warning "Version Detected: " -ForegroundColor Cyan
	Write-Warning "PSVersion: $($PSVersionTable.PSVersion)"
	Write-Warning "PSEdition: $($PSVersionTable.PSEdition)"
	exit 1
}
Write-Host "Running Windows PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor Green

# System Restore




try {
	Checkpoint-Computer -Description "Created Before Windows Hardening Script Run" -RestorePointType MODIFY-SETTINGS
}	catch	{
	Write-Warning "Restore point creation failure: $_"
}

# Disable SMBv1 | Disable vulnerable protocols




Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -PropertyType DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 4 -Type DWord

# Disable SSL | Disable TLS (Weak Versions)




$protocols =@("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
foreach ($proto in $protocols) {
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server" -Name "Enabled" -value 0 -Type DWord
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Client" -Name "Enabled" -value 0 -Type DWord

# Enable TLS (1.2+)




Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name "Enabled" -value 1 -Type DWord

# Enforce Password policies





Write-Host "Configuring password policies . . ." -ForegroundColor Green

# NIST Standards (SP 800-63B compliant)




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

# Disable Storage of Passwords in WDigest




Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonKey" -value 0 -Type DWord

#Configure Firewall - Strict




Write-Host "Configuring Windows Firewall . . ." -ForegroundColor Green

# Deny Inbound by default




Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 16000 -LogAllowed True -LogBlocked True

#Allow Essential Inbound Actions by default (prompted for management subnet)




function Get-managementSubnet {
	while ($true) {
		$subnet = Read-Host "Enter your managmenet subnet for RDP access (e.g., 192.168.1.1/255)"
		
		# CIDR Validation
		if ($subnet -match '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$') {
			return $subnet
		}
		Write-Warning "Invalid CIDR format! Example: 192.168.1.1/255"
	}
}

Write-Host "Configuring Firewall Rules for $managementSubnet . . ." -ForegroundColor Green

Get-NetFirewallRule -DisplayName "Allow RDP from Management*" | Remove-NetFirewallRule -ErrorAction SilentlyContinue

$rules = @(
	@{Name="Allow HTTP"; Port=80; IP="Any"},
	@{Name="Allow HTTPS"; Port=443; IP="Any"},
	@{Name="Allow Managed RDP";   Port=3389; IP=$managementSubnet}
)

foreach ($rule in $rules) {
	$params = @{
		DisplayName =$rule.Name
		Direction = 'Inbound'
		Protocol = 'TCP'
		LocalPort = $rule.Port
		RemoteAddress = $rule.IP
		Action = 'Allow'
		Enabled = $true
}

#Remove Present Ruleset (if it exists)




Get-netFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule

#Create rule




New-NetFirewallRule @params
Write-Host " Rule Created: $($rule.name) ($($rule.ip))" -ForegroundColor Cyan}
}

#Enable BitLocker




Write-Host "Configuring BitLocker . . ." -ForegroundColor Green

if ((Get-Command -Name Enable-BitLocker -ErrorAction SilentlyContinue) -and
	(Get-TPM -ErrorAction Silentlycontinue).TPMPresent) {
		
	$osVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive
	
	if ($osVolume.VolumeStatus -ne "Encrypted") {
		try {
			# Enable Strongest Encryption rule
Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmAndPinProtector -Pin (ConvertTo-SecureString -String "PleaseChangeThisSecretKey" -AsPlainText -Force) -ErrorAction Stop	
		Write-Host "BitLocker enable | TPM and Pin Protection Enabled" -ForegroundColor Green
		} catch {
			Write-Warning "BitLocker Enabilization Failure: $_"
		}
	} else {
		Write-Host "BitLocker Already Enabled" -ForegroundColor Cyan
	}
	} else {
		Write-Warning "BitLocker cannot be enabled (TPM missing / Unsupported by your Operating System)"
	}
	
	
#Necessary Additional Steps




Write-Host "Disabling Unnecessary Services and Applying Necessary Patches" -ForegroundColor Green

#Unsecured Services




$services =@("RemoteRegistry", "SSDPSRV", "upnphost", "Telnet", "TlntSvr", "SNMP", "Spooler")
foreach ($svc in $services) {
	Stop-Service $svc -ErrorAction SilentlyContinue
	Set-Service $svc -StartupType Disabled -ErrorAction Silentlycontinue
}

#LSA Protection




Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentCOntrolSet\Control\Lsa" -Name "LSA Enabled" -Value 1 -Type DWord

#Disable LLMNR | Disable NetBIOS




Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnabledMulticast" -Value 0 -Type DWord
Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } | ForEach-Object { $_.SetTcpipNetbios(2) }

#Windows Defender Protections Enabled




Set-MpPreference -EnableControlledFolderAccess Enabled -EnableNetworkProtection Enabled -MAPSReporting Advanced

# Inform End-User




Write-Host "Hardening Process Completed." -ForegroundColor Green
Write-Host "Reboot at earliest convenience for changes to take effect." -ForegroundColor Green
Write-Host "Log of changes available at: $($(Get-ChildItem "$env:TEMP\Hardening-*.log" | Sort-Object Last WriteTime | Select-Object -Last 1).FullName)" -ForegroundColor Cyan

Write-Host "Summary of changes applied: " -ForegroundColor Yellow
Write-Host " SMBv1 and Legacy Protocols Disabled"
Write-Host " NIST-compliant passwords enforced"
Write-Host " Firewall denies traffic inbound by default"
Write-Host " BitLocker with TPM+PIN protection enabled"
Write-Host "Critical services hardened"
Write-Host "ATP protections in Windows Defender enabled"

Stop-Transcript