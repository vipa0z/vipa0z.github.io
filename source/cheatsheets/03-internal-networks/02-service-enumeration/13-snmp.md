# SNMP (Port 161, 162)

Enumerate network devices using SNMP (Simple Network Management Protocol) to discover system information, credentials, and misconfigurations.
SNMP is used for monitoring and managing network devices like routers, switches, servers, and IoT devices.

## Quick Reference

### Brute Force Community Strings
```bash
# onesixtyone
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.10.10.10

# Nmap
nmap -sU -p161 --script snmp-brute --script-args snmp-brute.communitiesdb=/usr/share/seclists/Discovery/SNMP/snmp.txt 10.10.10.10
```

### Enumerate SNMP Data
```bash
# Dump all SNMP data
snmpwalk -v2c -c public 10.10.10.10

# Enumerate specific OID
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.1
```

## SNMP Versions

### SNMPv1
- No built-in authentication
- Community strings transmitted in cleartext
- Vulnerable to sniffing and replay attacks

### SNMPv2c
- Uses community strings for authentication
- Transmission in cleartext
- Most commonly deployed version

### SNMPv3
- Username and password authentication
- Encryption for transmission
- Complex setup, less commonly used

## Community Strings

### Common Default Strings
```
public
private
manager
```

### Brute Force with onesixtyone
```bash
# Single target
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.10.10.10

# Multiple targets
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt -i targets.txt

# Custom wordlist
onesixtyone -c community_strings.txt 10.10.10.10
```

### Brute Force with Nmap
```bash
nmap -sU -p161 --script snmp-brute 10.10.10.10
nmap -sU -p161 --script snmp-brute --script-args snmp-brute.communitiesdb=wordlist.txt 10.10.10.10
```

### Brute Force with braa
```bash
# Brute force with known string
braa public@10.10.10.10:.1.3.6.*
```

## SNMP Enumeration

### snmpwalk (Dump All Data)
```bash
# SNMPv1
snmpwalk -v1 -c public 10.10.10.10

# SNMPv2c
snmpwalk -v2c -c public 10.10.10.10

# SNMPv3
snmpwalk -v3 -u username -l authPriv -a SHA -A password -x AES -X password 10.10.10.10
```

### snmpbulkwalk (Faster Enumeration)
```bash
snmpbulkwalk -v2c -c public 10.10.10.10
```

### Enumerate Specific OIDs
```bash
# System information
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.1

# Network interfaces
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.2

# Running processes
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.25.4.2.1.2

# Installed software
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.25.6.3.1.2

# User accounts
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.4.1.77.1.2.25

# TCP connections
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.6.13.1.3

# Storage information
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.25.2
```

## snmpbw.pl (Comprehensive Enumeration)

### Gather All SNMP Data
```bash
# Download script
wget https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/wordlists/snmp_default_pass.txt

# Run enumeration
snmpbw.pl 10.10.10.10 public 2 32
snmpbw.pl 10.10.10.10 <community-string> 2 32
```

### Extract System Descriptions
```bash
grep ".1.3.6.1.2.1.1.1.0" *.snmp
```

### Find Trap Data (Discover Other Hosts)
```bash
grep -i "trap" *.snmp
```

### Find Failed Login Attempts
```bash
grep -i "fail" *.snmp
```

## Nmap SNMP Scripts

### Enumeration Scripts
```bash
# All SNMP scripts
nmap -sU -p161 --script snmp-* 10.10.10.10

# Specific scripts
nmap -sU -p161 --script snmp-info,snmp-interfaces,snmp-processes 10.10.10.10

# System info
nmap -sU -p161 --script snmp-sysdescr 10.10.10.10

# Network interfaces
nmap -sU -p161 --script snmp-interfaces 10.10.10.10

# Running processes
nmap -sU -p161 --script snmp-processes 10.10.10.10

# Windows users
nmap -sU -p161 --script snmp-win32-users 10.10.10.10

# Windows services
nmap -sU -p161 --script snmp-win32-services 10.10.10.10
```

## Metasploit SNMP Modules

### Enumeration
```bash
# SNMP login scanner
use auxiliary/scanner/snmp/snmp_login
set RHOSTS 10.10.10.10
set PASS_FILE /usr/share/seclists/Discovery/SNMP/snmp.txt
run

# SNMP enumeration
use auxiliary/scanner/snmp/snmp_enum
set RHOSTS 10.10.10.10
set COMMUNITY public
run

# SNMP enum shares
use auxiliary/scanner/snmp/snmp_enumshares
set RHOSTS 10.10.10.10
set COMMUNITY public
run

# SNMP enum users
use auxiliary/scanner/snmp/snmp_enumusers
set RHOSTS 10.10.10.10
set COMMUNITY public
run
```

## Common OIDs

### System Information
```
1.3.6.1.2.1.1.1.0    - System Description
1.3.6.1.2.1.1.3.0    - System Uptime
1.3.6.1.2.1.1.4.0    - System Contact
1.3.6.1.2.1.1.5.0    - System Name
1.3.6.1.2.1.1.6.0    - System Location
```

### Network Information
```
1.3.6.1.2.1.2.2.1.2  - Interface descriptions
1.3.6.1.2.1.2.2.1.5  - Interface speeds
1.3.6.1.2.1.4.20.1.1 - IP addresses
1.3.6.1.2.1.4.21.1.1 - Routing table
```

### Process and Software
```
1.3.6.1.2.1.25.4.2.1.2  - Running processes
1.3.6.1.2.1.25.6.3.1.2  - Installed software
```

### Windows Specific
```
1.3.6.1.4.1.77.1.2.25   - Windows user accounts
1.3.6.1.4.1.77.1.2.3.1.1 - Windows shares
```

## Information Disclosure

### Sensitive Data in SNMP
- Email addresses
- SNMP community strings
- Password hashes
- Clear text passwords
- System OS information
- Network topology
- Running services and processes
- User accounts
- Installed software

## Notes

**MIB vs OID:**
- **MIB (Management Information Base)** - Human-readable dictionary mapping OIDs to names
- **OID (Object Identifier)** - Numeric address in SNMP tree (e.g., 1.3.6.1.2.1.1.1.0)
- MIBs explain what each OID means, devices only understand OIDs

**Dangerous Settings:**
- `rwuser noauth` - Provides access to full OID tree without authentication
- `rwcommunity <string> <IP>` - Provides full access regardless of source
- `rwcommunity6 <string> <IPv6>` - Same as above for IPv6

**Security Considerations:**
- SNMPv1 and v2c transmit community strings in cleartext
- Default community strings (public, private) are commonly used
- SNMP can expose extensive system information
- Write access (rw community strings) allows system modification

**Common Misconfigurations:**
- Using default community strings
- Allowing SNMP access from any IP
- Using SNMPv1/v2c instead of SNMPv3
- Exposing sensitive information in MIB tables
- Not restricting SNMP to management networks

**Enumeration Tips:**
- Start with onesixtyone for fast community string discovery
- Use snmpwalk to dump all available data
- Search for "fail", "password", "trap" in output
- Check for user accounts and running processes
- Look for network topology information
- Community strings often match hostnames
