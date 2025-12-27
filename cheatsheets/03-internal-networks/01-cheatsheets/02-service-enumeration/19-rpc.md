# RPC (Port 135, 111)

Enumerate Windows and Linux RPC (Remote Procedure Call) services to discover SMB shares, users, and system information.
RPC enables inter-process communication and is heavily used in Windows domains for SMB, Active Directory, and administrative tasks.

## Quick Reference

### Windows RPC (Port 135)
```bash
# Enumerate with rpcclient (null session)
rpcclient -U "" -N 10.10.10.10

# Enumerate with credentials
rpcclient -U 'username%password' 10.10.10.10
```

### Linux RPC (Port 111)
```bash
# List RPC services
rpcinfo -p 10.10.10.10
```

## Windows RPC Enumeration

### rpcclient (Null Session)
```bash
# Connect with null session
rpcclient -U "" -N 10.10.10.10
rpcclient -U "" 10.10.10.10

# Connect with credentials
rpcclient -U 'username%password' 10.10.10.10
rpcclient -U 'DOMAIN\username%password' 10.10.10.10
```

### rpcclient Commands

#### Server Information
```bash
# Server info
srvinfo

# Enumerate domains
enumdomains

# Query domain info
querydominfo
```

#### Share Enumeration
```bash
# List all shares
netshareenumall

# Get info about specific share
netsharegetinfo <share_name>
```

#### User Enumeration
```bash
# Enumerate domain users
enumdomusers

# Query specific user by RID
queryuser <RID>

# Example: queryuser 0x457
queryuser 0x457

# Get user groups
queryusergroups <RID>
```

#### Group Enumeration
```bash
# Enumerate domain groups
enumdomgroups

# Query specific group
querygroup <RID>

# Get group members
querygroupmem <RID>
```

#### Alias Enumeration
```bash
# Enumerate aliases (local groups)
enumalsgroups builtin

# Query alias members
queryaliasmem builtin <RID>
```

### RID Cycling / Brute Force

#### Manual RID Cycling
```bash
# Enumerate users by RID
for i in $(seq 500 1100); do
    rpcclient -N -U "" 10.10.10.10 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo ""
done
```

#### CrackMapExec RID Brute
```bash
# RID brute force
nxc smb 10.10.10.10 -u 'guest' -p '' --rid-brute

# With credentials
nxc smb 10.10.10.10 -u 'username' -p 'password' --rid-brute
```

#### NetExec RID Brute
```bash
nxc smb 10.10.10.10 -u 'guest' -p '' --rid-brute
```

### Understanding RIDs

**RID (Relative Identifier):**
- Unique identifier for objects in Windows
- Represented in hexadecimal format
- Combined with domain SID to create unique SID

**Example:**
- Domain SID: `S-1-5-21-3842939050-3880317879-2865463114`
- User RID: `0x457` (hex) = `1111` (decimal)
- Full User SID: `S-1-5-21-3842939050-3880317879-2865463114-1111`

**Common RIDs:**
- 500 - Administrator
- 501 - Guest
- 512 - Domain Admins
- 513 - Domain Users
- 514 - Domain Guests
- 515 - Domain Computers
- 516 - Domain Controllers

## Impacket Tools

### samrdump.py
```bash
# Dump user information
samrdump.py 10.10.10.10

# With credentials
samrdump.py DOMAIN/username:password@10.10.10.10
```

### lookupsid.py
```bash
# Enumerate users via SID lookup
lookupsid.py DOMAIN/username:password@10.10.10.10

# Brute force RIDs
lookupsid.py DOMAIN/username:password@10.10.10.10 20000
```

## SMB Enumeration via RPC

### smbmap
```bash
# List shares (null session)
smbmap -H 10.10.10.10

# With credentials
smbmap -u username -p password -H 10.10.10.10

# List share contents
smbmap -u username -p password -H 10.10.10.10 -R 'Share Name'

# Download file
smbmap -u username -p password -H 10.10.10.10 --download 'Share\file.txt'
```

### CrackMapExec
```bash
# Enumerate shares
nxc smb 10.10.10.10 --shares -u '' -p ''
nxc smb 10.10.10.10 --shares -u 'username' -p 'password'

# Spider shares
nxc smb 10.10.10.10 -u username -p password -M spider_plus --share 'Share Name'

# Enumerate users
nxc smb 10.10.10.10 -u username -p password --users

# Enumerate groups
nxc smb 10.10.10.10 -u username -p password --groups

# Enumerate logged-on users
nxc smb 10.10.10.10 -u username -p password --loggedon-users
```

## enum4linux

### Basic Enumeration
```bash
# Full enumeration
enum4linux -a 10.10.10.10

# User enumeration
enum4linux -U 10.10.10.10

# Share enumeration
enum4linux -S 10.10.10.10

# Group enumeration
enum4linux -G 10.10.10.10

# Password policy
enum4linux -P 10.10.10.10
```

### enum4linux-ng
```bash
# Advanced enumeration
./enum4linux-ng.py 10.10.10.10 -A -C

# With credentials
./enum4linux-ng.py 10.10.10.10 -u username -p password -A
```

## Linux RPC (Port 111)

### rpcinfo
```bash
# List RPC services
rpcinfo -p 10.10.10.10

# Query specific program
rpcinfo -s 10.10.10.10

# TCP services
rpcinfo -t 10.10.10.10 <program> <version>

# UDP services
rpcinfo -u 10.10.10.10 <program> <version>
```

### Nmap
```bash
# RPC enumeration
nmap -p 111 --script rpcinfo 10.10.10.10

# NFS via RPC
nmap -p 111 --script nfs-* 10.10.10.10
```

## Common Workflow

### Windows RPC Assessment
```bash
# 1. Check for null session
rpcclient -U "" -N 10.10.10.10

# 2. Enumerate users
enumdomusers

# 3. Enumerate shares
netshareenumall

# 4. Query domain info
querydominfo

# 5. RID cycling for hidden users
for i in $(seq 500 1100); do
    rpcclient -N -U "" 10.10.10.10 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name" && echo ""
done

# 6. Use CrackMapExec for comprehensive enum
nxc smb 10.10.10.10 -u '' -p '' --rid-brute --shares --users
```

### Linux RPC Assessment
```bash
# 1. Enumerate RPC services
rpcinfo -p 10.10.10.10

# 2. Check for NFS
showmount -e 10.10.10.10

# 3. Nmap RPC scripts
nmap -p 111 --script rpcinfo,nfs-* 10.10.10.10
```

## Metasploit Modules

### SMB Enumeration
```bash
# SMB version
use auxiliary/scanner/smb/smb_version
set RHOSTS 10.10.10.10
run

# SMB enumeration
use auxiliary/scanner/smb/smb_enumusers
set RHOSTS 10.10.10.10
run

# SMB shares
use auxiliary/scanner/smb/smb_enumshares
set RHOSTS 10.10.10.10
run
```

## Notes

**Windows RPC (Port 135):**
- Used for DCOM, WMI, and various Windows services
- Enables SMB enumeration via rpcclient
- Null sessions may be allowed (misconfiguration)
- RID cycling reveals hidden users
- Essential for Active Directory enumeration

**Linux RPC (Port 111):**
- Portmapper service
- Maps RPC program numbers to network ports
- Used by NFS, NIS, and other services
- Less commonly exploited than Windows RPC

**Null Sessions:**
- Anonymous connection to IPC$ share
- Allows enumeration without credentials
- Disabled by default on modern Windows
- Common misconfiguration on older systems

**RID Cycling:**
- Brute force user enumeration via RIDs
- Reveals users not shown by enumdomusers
- Can discover service accounts and hidden users
- Works even with restricted enumeration

**Security Considerations:**
- RPC exposes extensive system information
- Null sessions allow anonymous enumeration
- User and group information disclosed
- Share permissions can be enumerated
- Password policies revealed

**Common Misconfigurations:**
- Null sessions enabled
- Anonymous RPC access allowed
- Overly permissive share permissions
- Weak password policies
- Service accounts with descriptive names

**Attack Surface:**
- User enumeration
- Share enumeration
- Password policy discovery
- Group membership disclosure
- Service account identification
- Domain trust relationships

**Tools Comparison:**
- **rpcclient** - Interactive RPC client, manual enumeration
- **enum4linux** - Automated enumeration wrapper
- **CrackMapExec** - Modern, feature-rich SMB/RPC tool
- **smbmap** - Share enumeration and file operations
- **Impacket** - Python-based RPC tools
