# VirtualBox Lab Setup

# VM Settings Summary
- Windows 11 Pro
	- 8GB RAM, 4 CPU cores, EFI Enabled, VT-x not available (disabled), NAT network (avoid vm breaches)

- Windows Server 2019
	 - 4GB RAM, 2 CPU cores, NAT + Internal Network

- Ubuntu Server
	- 2 GB RAM, 2 CPU cores, NAT + Internal Network 

# Security Concerns
- Disabled shared folders and clipboard
- Disabled drag-and-drop, disallowed USB passthrough
- Snapshots created for rollback before each major change or test