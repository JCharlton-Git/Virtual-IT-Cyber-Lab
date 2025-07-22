# Problem Presented
- Installer freezes at 52% during fresh installation

# Solution(s) Applied
- Enabled EFI
- Increased RAM from 2 to 8GB, CPU from 2 to 4 cores
- Added registry keys to bypass TPM and Secure Boot:
	HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig
	BypassTPMCheck = 1 (DWORD)
	BypassSecureBootCheck =1 (DWORD)

# Miscellanious Extra Issues
- Skipped microsoft account using "start ms-cxh:localonly" during account creation to use a username and password