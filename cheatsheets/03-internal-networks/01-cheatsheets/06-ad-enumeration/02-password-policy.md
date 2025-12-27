# Password Policy Enumeration

Retrieve domain password policy to inform password spraying attacks and avoid account lockouts.
Understanding password requirements helps craft targeted password lists and prevents triggering security alerts.

## Quick Reference

```bash
# RPC password policy query
rpcclient -U "" -N 172.16.5.5
rpcclient $> getdompwinfo

# NetExec anonymous check
nxc smb 172.16.5.5 -u "anonymous" -p ""

# Windows net.exe
net accounts
```

## SMB/RPC Password Policy Retrieval

### RPCClient - Anonymous Access

```bash
rpcclient -U "" -N 172.16.5.5
rpcclient $> querydominfo
rpcclient $> getdompwinfo
```

Example output:

```
Domain:         BLACKWOOD
Total Users:    3650
Total Groups:   0
Total Aliases:  37
```

### Enum4linux-ng - Comprehensive Enumeration

```bash
enum4linux-ng -P 172.16.5.5 -oA ilfreight
```

View results:

```bash
cat ilfreight.json
```

### NetExec - Check Anonymous Access

```bash
nxc smb 172.16.5.5 -u "anonymous" -p ""
```

### Windows - SMB Null Session

```cmd
net use \\DC01\ipc$ "" /u:""
```

## LDAP Password Policy Enumeration

### LDAPSearch - Anonymous Bind

```bash
ldapsearch -h 172.16.5.5 -x -b "DC=BLACKWOOD,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

### LDAPSearch - Authenticated Query

```bash
ldapsearch -h 172.16.5.5 -x -D "CN=svc_ldap,OU=Service Accounts,DC=BLACKWOOD,DC=LOCAL" -w 'P@ssw0rd!' -b "DC=BLACKWOOD,DC=LOCAL" -s sub "(objectClass=*)" sAMAccountName
```

#### LDAPSearch Options

| Option                             | Meaning                                                                                     |
| ---------------------------------- | ------------------------------------------------------------------------------------------- |
| `-h 172.16.5.5`                    | Connect to LDAP server at this IP                                                           |
| `-x`                               | Use simple bind (username + password, not SASL)                                             |
| `-D "CN=...,OU=...,DC=...,DC=..."` | Bind DN (the full distinguished name of the account you're authenticating with)             |
| `-w 'P@ssw0rd!'`                   | Password for the bind account (wrap in single quotes if it contains special characters)     |
| `-b "DC=..."`                      | Base DN for the search                                                                      |
| `-s sub`                           | Search scope: subtree                                                                       |
| `"(objectClass=*)"`                | Match all objects (can be more specific like `(sAMAccountName=jsmith)`)                     |
| `sAMAccountName`                   | Return only this attribute (optional — omit to get everything)                              |

## Windows Native Enumeration

### Net.exe - Local Password Policy

```cmd
net accounts
```

Example output:

```
Minimum password age (days):                          1
Maximum password age (days):                          Unlimited
Minimum password length:                              8
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
```

### PowerView - Domain Password Policy

```powershell
Import-Module .\PowerView.ps1
Get-DomainPolicy
```

## Common Workflows

### Anonymous Policy Enumeration

1. Attempt anonymous SMB/RPC bind
2. Query password policy with rpcclient getdompwinfo
3. Check for lockout threshold and duration
4. Plan password spray attempts accordingly

### Authenticated Policy Retrieval

1. Use valid domain credentials
2. Query via LDAP or PowerView for detailed policy
3. Identify complexity requirements
4. Note password history length for credential reuse attacks

## Notes

### Default Domain Password Policy

When a new domain is created, the default password policy is:

| Policy                                      | Default Value |
| ------------------------------------------- | ------------- |
| Enforce password history                    | 24 days       |
| Maximum password age                        | 42 days       |
| Minimum password age                        | 1 day         |
| Minimum password length                     | 7             |
| Password must meet complexity requirements  | Enabled       |
| Store passwords using reversible encryption | Disabled      |
| Account lockout duration                    | Not set       |
| Account lockout threshold                   | 0             |
| Reset account lockout counter after         | Not set       |

### Password Complexity Requirements

When password complexity is enabled (`PasswordComplexity=1`), passwords must contain 3 out of 4 of the following:
- Uppercase letter
- Lowercase letter
- Number
- Special character

Note: Passwords like `Password1` or `Welcome1` satisfy complexity requirements but are still weak.

### Key Considerations for Password Spraying

- **Lockout Threshold**: Number of failed attempts before account locks (often 5)
- **Lockout Duration**: How long accounts remain locked (often 30 minutes)
- **Lockout Reset Counter**: Time before failed attempt counter resets

**Best Practice**: If lockout threshold is 5, attempt maximum 2-3 passwords per spray cycle with significant time delays between cycles to avoid lockouts.

### Tools for Password Policy Enumeration

- **windapsearch.py**: LDAP-based enumeration
- **ldapsearch**: Manual LDAP queries
- **ad-ldapdomaindump.py**: Comprehensive LDAP dumping
- **enum4linux-ng**: Multi-protocol enumeration
- **rpcclient**: RPC-based queries
- **PowerView**: PowerShell-based enumeration from Windows
- **NetExec**: Modern SMB enumeration tool
